"""보안 점검 도구 화면.

판단은 모두 actions·integrity_check 가 하고, 이 파일은 버튼과 결과 그리기만 맡는다.
"""

from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk
from checker import safe_path

from seccheck import this_pc
from seccheck.actions import analyze_file, analyze_this_pc, baseline_time
from seccheck.integrity_check import make_baseline, verify
from seccheck.log_check import KST
from seccheck.report_text import render_integrity_report, render_log_report
from seccheck.ui_common import BackgroundTask, ConfirmDialog, ResultPanel, font

APP_TITLE = "보안 점검 도구"
PAD = 18


def _now_kst():
    return datetime.now(KST)


class LogTab(ctk.CTkFrame):
    IDLE = "분석할 로그를 골라 주세요"

    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._task = None

        ctk.CTkLabel(self, text="윈도우 보안 로그에서 로그인 반복 실패, 로그 삭제, 계정 변경을 찾습니다.",
                     font=font(14)).pack(anchor="w")

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", pady=(10, 0))
        self.open_button = ctk.CTkButton(buttons, text="로그 파일 열기…", font=font(15, "bold"), height=40,
                                         command=self._open_file)
        self.open_button.pack(side="left")
        self.pc_button = ctk.CTkButton(buttons, text="이 PC 점검", font=font(15, "bold"), height=40,
                                       command=self._check_this_pc)
        self.pc_button.pack(side="left", padx=(10, 0))
        self.pc_hint = ctk.CTkLabel(buttons, text="", font=font(12), text_color="#607D8B")
        self.pc_hint.pack(side="left", padx=(12, 0))
        self._update_pc_button()

        self.progress_row = ctk.CTkFrame(self, fg_color="transparent")
        self.progress = ctk.CTkProgressBar(self.progress_row, mode="indeterminate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.progress_text = ctk.CTkLabel(self.progress_row, text="", font=font(12), width=160)
        self.progress_text.pack(side="left", padx=10)
        self.cancel_button = ctk.CTkButton(self.progress_row, text="취소", width=70, font=font(13),
                                           fg_color="#78909C", command=self._cancel)
        self.cancel_button.pack(side="left")

        self.result = ResultPanel(self, "로그분석", self.IDLE)
        self.result.pack(fill="both", expand=True, pady=(14, 0))

    # ── 이 PC 점검 버튼 상태 ──
    def _update_pc_button(self):
        if not this_pc.is_windows():
            self.pc_button.configure(state="disabled", fg_color="#CFD8DC", text_color_disabled="#78909C")
            self.pc_hint.configure(text="윈도우에서만 쓸 수 있습니다")
        elif not this_pc.is_admin():
            self.pc_hint.configure(text="관리자 권한이 필요합니다")
        else:
            self.pc_hint.configure(text="지금 쓰는 PC 의 보안 로그를 분석합니다")

    # ── 동작 ──
    def _open_file(self):
        path = filedialog.askopenfilename(title="분석할 보안 로그 파일 선택",
                                          filetypes=[("이벤트 로그", "*.evtx"), ("모든 파일", "*.*")])
        if path:
            self._start(lambda progress, cancelled: analyze_file(path, progress, cancelled), path)

    def _check_this_pc(self):
        if not this_pc.is_admin():
            if messagebox.askyesno(APP_TITLE, "이 PC 의 보안 로그를 읽으려면 관리자 권한이 필요합니다.\n"
                                              "관리자 권한으로 다시 실행할까요?"):
                if this_pc.relaunch_as_admin():
                    self.winfo_toplevel().destroy()
                else:
                    messagebox.showwarning(APP_TITLE, "관리자 권한으로 다시 실행하지 못했습니다.")
            return
        self._start(lambda progress, cancelled: analyze_this_pc(progress, cancelled), "이 PC 의 보안 로그")

    def _start(self, work, source):
        self._set_busy(True)
        self.result.clear("분석하는 중입니다…")
        self._task = BackgroundTask(
            self, work,
            on_done=lambda report: self._show(report, source),
            on_error=self._failed,
            on_progress=lambda n: self.progress_text.configure(text=f"읽은 기록: {n:,}건"),
            on_cancelled=self._cancelled)

    def _cancel(self):
        if self._task:
            self._task.cancel()
            self.progress_text.configure(text="취소하는 중…")

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.open_button.configure(state=state)
        if this_pc.is_windows():
            self.pc_button.configure(state=state)
        if busy:
            self.progress_text.configure(text="파일을 여는 중…")
            self.progress_row.pack(fill="x", pady=(12, 0), before=self.result)
            self.progress.start()
        else:
            self.progress.stop()
            self.progress_row.pack_forget()
            self._task = None

    def _show(self, report, source):
        self._set_busy(False)
        basis = f"분석한 기록: {report.total:,}건"
        if report.period:
            basis += f"  ({report.period[0]:%Y-%m-%d %H:%M} ~ {report.period[1]:%Y-%m-%d %H:%M})"
        basis += f"   ·   대상: {safe_path(source)}"
        self.result.show(report.level, report.findings, basis,
                         render_log_report(report, safe_path(source), _now_kst()))

    def _cancelled(self):
        self._set_busy(False)
        self.result.clear("분석을 취소했습니다")

    def _failed(self, error):
        self._set_busy(False)
        self.result.clear("분석하지 못했습니다")
        messagebox.showerror(APP_TITLE, f"분석 중 문제가 생겼습니다.\n{error}")


class IntegrityTab(ctk.CTkFrame):
    IDLE = "검사할 폴더를 골라 주세요"

    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._folder = None
        self._key_file = None

        ctk.CTkLabel(self, text="폴더의 기준선을 만들어 두고, 나중에 파일이 바뀌거나 지워지거나 새로 생겼는지 검사합니다.",
                     font=font(14)).pack(anchor="w")

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", pady=(10, 0))
        ctk.CTkButton(row, text="폴더 선택…", font=font(15, "bold"), height=40,
                      command=self._choose_folder).pack(side="left")
        self.folder_label = ctk.CTkLabel(row, text="선택한 폴더 없음", font=font(13), text_color="#607D8B")
        self.folder_label.pack(side="left", padx=12)

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", pady=(10, 0))
        self.baseline_button = ctk.CTkButton(actions, text="기준선 만들기", font=font(15, "bold"), height=40,
                                             state="disabled", command=self._make_baseline)
        self.baseline_button.pack(side="left")
        self.verify_button = ctk.CTkButton(actions, text="검사하기", font=font(15, "bold"), height=40,
                                           state="disabled", command=self._verify)
        self.verify_button.pack(side="left", padx=(10, 0))

        # 고급 설정: 비밀키를 USB 등 검사 대상과 다른 곳에 두기
        advanced = ctk.CTkFrame(self, fg_color="transparent")
        advanced.pack(fill="x", pady=(10, 0))
        self.key_switch = ctk.CTkCheckBox(advanced, text="고급: 비밀키를 다른 곳에 보관 (USB 등)", font=font(12),
                                          command=self._toggle_key)
        self.key_switch.pack(side="left")
        self.key_button = ctk.CTkButton(advanced, text="위치 지정…", width=90, font=font(12),
                                        command=self._choose_key)
        self.key_label = ctk.CTkLabel(advanced, text="", font=font(12), text_color="#607D8B")

        self.progress = ctk.CTkProgressBar(self, mode="indeterminate")

        self.result = ResultPanel(self, "무결성", self.IDLE)
        self.result.pack(fill="both", expand=True, pady=(14, 0))

    def _choose_folder(self):
        folder = filedialog.askdirectory(title="검사할 폴더 선택")
        if not folder:
            return
        self._folder = folder
        self.folder_label.configure(text=safe_path(folder), text_color="#263238")
        self.baseline_button.configure(state="normal")
        self.verify_button.configure(state="normal")
        made = baseline_time(folder)
        self.result.clear(f"기준선 있음 ({made:%Y-%m-%d %H:%M} 만듦) — [검사하기]를 눌러 주세요" if made
                          else "기준선이 없습니다 — 먼저 [기준선 만들기]를 눌러 주세요")

    def _toggle_key(self):
        if self.key_switch.get():
            self.key_button.pack(side="left", padx=(10, 0))
            self.key_label.pack(side="left", padx=(8, 0))
        else:
            self.key_button.pack_forget()
            self.key_label.pack_forget()
            self._key_file = None
            self.key_label.configure(text="")

    def _choose_key(self):
        path = filedialog.asksaveasfilename(title="비밀키 파일 위치 (없으면 새로 만듭니다)",
                                            initialfile="integrity.key", confirmoverwrite=False,
                                            filetypes=[("비밀키", "*.key"), ("모든 파일", "*.*")])
        if path:
            self._key_file = path
            self.key_label.configure(text=safe_path(path))

    def _key_or_warn(self):
        if self.key_switch.get() and not self._key_file:
            messagebox.showwarning(APP_TITLE, "비밀키 위치를 먼저 지정해 주세요.")
            return False, None
        return True, self._key_file if self.key_switch.get() else None

    def _make_baseline(self):
        ok, key_file = self._key_or_warn()
        if not ok:
            return
        made = baseline_time(self._folder)
        if made and not ConfirmDialog(
                self, "기준선 다시 만들기",
                f"이미 기준선이 있습니다 ({made:%Y-%m-%d %H:%M} 만듦).\n\n"
                "새로 만들면 이전 기준이 사라집니다. 파일이 이미 바뀐 상태라면 "
                "바뀐 내용이 정상으로 기록됩니다.\n\n먼저 [검사하기]로 확인하는 것을 권합니다.",
                yes_text="새로 만들기", no_text="취소").ask():
            return
        folder = self._folder
        self._run(lambda progress, cancelled: make_baseline(folder, replace=bool(made), key_file=key_file),
                  "기준선 만들기")

    def _verify(self):
        ok, key_file = self._key_or_warn()
        if not ok:
            return
        folder = self._folder
        self._run(lambda progress, cancelled: verify(folder, key_file=key_file), "검사하기")

    def _run(self, work, action):
        self._set_busy(True)
        self.result.clear(f"{action} 중입니다…")
        folder = self._folder
        BackgroundTask(self, work,
                       on_done=lambda report: self._show(report, folder, action),
                       on_error=self._failed)

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.baseline_button.configure(state=state)
        self.verify_button.configure(state=state)
        if busy:
            self.progress.pack(fill="x", pady=(12, 0), before=self.result)
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def _show(self, report, folder, action):
        self._set_busy(False)
        noun = "기록한" if action == "기준선 만들기" else "검사한"
        basis = f"{noun} 파일: {report.checked_count:,}개   ·   대상 폴더: {safe_path(folder)}"
        self.result.show(report.level, report.findings, basis,
                         render_integrity_report(report, safe_path(folder), action, _now_kst()))

    def _failed(self, error):
        self._set_busy(False)
        self.result.clear("검사하지 못했습니다")
        messagebox.showerror(APP_TITLE, f"검사 중 문제가 생겼습니다.\n{error}")


class App(ctk.CTk):
    tab_names = ("로그 분석", "파일 무결성")

    def __init__(self):
        ctk.set_appearance_mode("light")
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x700")
        self.minsize(860, 620)

        tabs = ctk.CTkTabview(self, segmented_button_font=font(15, "bold"))
        tabs.pack(fill="both", expand=True, padx=PAD, pady=(8, PAD))
        LogTab(tabs.add(self.tab_names[0])).pack(fill="both", expand=True, padx=8, pady=8)
        IntegrityTab(tabs.add(self.tab_names[1])).pack(fill="both", expand=True, padx=8, pady=8)


def main():
    App().mainloop()
