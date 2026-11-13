"""두 탭이 함께 쓰는 화면 부품.

- BackgroundTask : 분석을 화면과 따로 돌린다 (창이 얼지 않게). 화면 갱신은 after() 로만 한다.
- ResultPanel    : 판정 띠 + 근거 한 줄 + 항목 표 + [보고서 저장]
"""

import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from seccheck.verdict import Level
from seccheck.winevents import OperationCancelled

if sys.platform == "win32":
    FONT_FAMILY = "Malgun Gothic"
elif sys.platform == "darwin":
    FONT_FAMILY = "Apple SD Gothic Neo"
else:
    FONT_FAMILY = "Noto Sans CJK KR"

# 판정 색: 배경, 글자
LEVEL_COLORS = {
    Level.DANGER: ("#C62828", "#FFFFFF"),
    Level.CHECK: ("#F9A825", "#212121"),
    Level.OK: ("#2E7D32", "#FFFFFF"),
}
IDLE_COLORS = ("#ECEFF1", "#455A64")

LEVEL_GUIDE = {
    Level.DANGER: "아래 항목을 확인하고 담당자에게 알려 주세요.",
    Level.CHECK: "아래 이유로 결과를 확정할 수 없습니다. 내용을 확인해 주세요.",
    Level.OK: "발견된 문제가 없습니다.",
}
LEVEL_TAGS = {Level.DANGER: "위험", Level.CHECK: "확인", Level.OK: "정상"}


def font(size=14, weight="normal"):
    return ctk.CTkFont(family=FONT_FAMILY, size=size, weight=weight)


class BackgroundTask:
    """work(progress, cancelled) 를 별도 스레드에서 돌리고 결과를 화면 스레드로 넘긴다.

    tkinter 는 다른 스레드에서 화면을 건드리면 안 되므로, 작업 스레드는 큐에 넣기만 하고
    화면 스레드가 after() 로 큐를 들여다본다.
    """

    POLL_MS = 100

    def __init__(self, widget, work, on_done, on_error, on_progress=None, on_cancelled=None):
        self._widget = widget
        self._queue = queue.SimpleQueue()
        self._cancel = threading.Event()
        self._handlers = {"done": on_done, "error": on_error,
                          "progress": on_progress or (lambda n: None),
                          "cancelled": on_cancelled or (lambda: None)}
        threading.Thread(target=self._run, args=(work,), daemon=True).start()
        widget.after(self.POLL_MS, self._poll)

    def cancel(self):
        self._cancel.set()

    def _run(self, work):
        try:
            result = work(progress=lambda n: self._queue.put(("progress", n)), cancelled=self._cancel.is_set)
        except OperationCancelled:
            self._queue.put(("cancelled", None))
        except Exception as e:   # 예상 못 한 오류도 화면에서 안내한다
            self._queue.put(("error", e))
        else:
            self._queue.put(("done", result))

    def _poll(self):
        while True:
            try:
                kind, value = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                self._handlers["progress"](value)
                continue
            if kind == "cancelled":
                self._handlers["cancelled"]()
            else:
                self._handlers[kind](value)
            return
        try:
            self._widget.after(self.POLL_MS, self._poll)
        except tk.TclError:
            pass   # 창이 이미 닫혔다


class ConfirmDialog(ctk.CTkToplevel):
    """되돌릴 수 없는 동작의 확인 창. '예' 버튼을 눌렀을 때만 result 가 True.

    운영체제 기본 확인 창(messagebox)은 플랫폼마다 동작이 달라, 기본값과 닫기 동작을
    앱이 정할 수 있는 이 창을 쓴다. 기본 초점은 '아니오', Enter·Esc·창 닫기도 모두 '아니오'.
    """

    default_choice = "no"

    def __init__(self, master, title: str, message: str, yes_text: str = "예", no_text: str = "아니오"):
        super().__init__(master)
        self.result = False
        self.title(title)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        ctk.CTkLabel(self, text=message, font=font(14), justify="left", wraplength=460).pack(
            anchor="w", padx=24, pady=(22, 16))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(0, 20))
        self.no_button = ctk.CTkButton(row, text=no_text, font=font(14, "bold"), width=120, command=self.close)
        self.no_button.pack(side="right")
        self.yes_button = ctk.CTkButton(row, text=yes_text, font=font(14), width=120, fg_color="#C62828",
                                        hover_color="#8E0000", command=self._yes)
        self.yes_button.pack(side="right", padx=(0, 10))
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<Escape>", lambda e: self.close())
        self.bind("<Return>", lambda e: self.close())
        self.after(50, self.no_button.focus_set)

    def _yes(self):
        self.result = True
        self.destroy()

    def close(self):
        self.result = False
        self.destroy()

    def ask(self) -> bool:
        """창을 띄우고 사용자가 고를 때까지 기다린다."""
        self.grab_set()
        self.wait_window()
        return self.result


class ResultPanel(ctk.CTkFrame):
    """판정 띠, 근거, 항목 표, 보고서 저장 버튼."""

    def __init__(self, master, report_kind: str, idle_text: str):
        super().__init__(master, fg_color="transparent")
        self._report_kind = report_kind
        self._report_text = None

        self.banner = ctk.CTkFrame(self, corner_radius=8, fg_color=IDLE_COLORS[0])
        self.banner.pack(fill="x")
        self.verdict = ctk.CTkLabel(self.banner, text=idle_text, font=font(22, "bold"), text_color=IDLE_COLORS[1])
        self.verdict.pack(anchor="w", padx=18, pady=(14, 2))
        self.guide = ctk.CTkLabel(self.banner, text="", font=font(14), text_color=IDLE_COLORS[1])
        self.guide.pack(anchor="w", padx=18, pady=(0, 14))

        self.basis = ctk.CTkLabel(self, text="", font=font(13), text_color="#455A64")
        self.basis.pack(anchor="w", pady=(8, 4))

        # 저장 버튼을 먼저 아래에 붙여 둔다. 표를 먼저 넣으면 창이 작을 때 버튼이 밀려 잘린다.
        self.save_button = ctk.CTkButton(self, text="보고서 저장…", font=font(14), state="disabled",
                                         command=self._save)
        self.save_button.pack(side="bottom", anchor="e", pady=(10, 0))

        table = ctk.CTkFrame(self, fg_color="transparent")
        table.pack(fill="both", expand=True)
        style = ttk.Style(self)
        style.configure("Result.Treeview", font=(FONT_FAMILY, 12), rowheight=30)
        style.configure("Result.Treeview.Heading", font=(FONT_FAMILY, 12, "bold"))
        self.tree = ttk.Treeview(table, columns=("level", "message"), show="headings",
                                 style="Result.Treeview", height=5)
        self.tree.heading("level", text="구분")
        self.tree.heading("message", text="내용")
        self.tree.column("level", width=70, minwidth=60, stretch=False, anchor="center")
        self.tree.column("message", width=700, minwidth=300, stretch=True, anchor="w")
        for level, (bg, _) in LEVEL_COLORS.items():
            self.tree.tag_configure(level.name, foreground=bg)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def clear(self, idle_text: str):
        self.banner.configure(fg_color=IDLE_COLORS[0])
        self.verdict.configure(text=idle_text, text_color=IDLE_COLORS[1])
        self.guide.configure(text="", text_color=IDLE_COLORS[1])
        self.basis.configure(text="")
        self.tree.delete(*self.tree.get_children())
        self.save_button.configure(state="disabled")
        self._report_text = None

    def show(self, level: Level, findings, basis: str, report_text: str):
        bg, fg = LEVEL_COLORS[level]
        self.banner.configure(fg_color=bg)
        self.verdict.configure(text=level.label, text_color=fg)
        self.guide.configure(text=LEVEL_GUIDE[level], text_color=fg)
        self.basis.configure(text=basis)
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self.tree.insert("", "end", values=(LEVEL_TAGS[f.level], f.message), tags=(f.level.name,))
        self._report_text = report_text
        self.save_button.configure(state="normal")

    def _save(self):
        if not self._report_text:
            return
        path = filedialog.asksaveasfilename(
            title="보고서 저장", defaultextension=".txt",
            initialfile=f"보안점검_{self._report_kind}_{datetime.now():%Y%m%d_%H%M}.txt",
            filetypes=[("텍스트 파일", "*.txt")])
        if not path:
            return
        try:
            # utf-8-sig: 메모장·한글·엑셀 등 윈도우 프로그램이 한글을 깨지지 않게 읽는다
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write(self._report_text)
        except OSError as e:
            messagebox.showerror("보고서 저장", f"보고서를 저장하지 못했습니다.\n{e}")
            return
        messagebox.showinfo("보고서 저장", f"보고서를 저장했습니다.\n{path}")
