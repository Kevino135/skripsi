#!/usr/bin/env python3

import re
import os
import json
import passwordmeter
import pkg_resources
from tkinter import *
from tkinter import ttk
import platform
from cryptography.fernet import Fernet


def index_containing_substring(the_list, substring):
    for i, s in enumerate(the_list):
        if substring in s:
              return i


def getPasswordComplexity(password):
    meter = passwordmeter.Meter(settings=dict(factors="length,charmix"))
    # meter = passwordmeter.Meter()
    strength = meter.test(password)[0]

    return strength


# filter string -> only get password
def getPasswordOnly(wordlist, m_precise):
    regex_password_acc = ".*(?:{})[\s=(:'\"<>]+([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\$=\+\-\*\^\?\&\~\%]*)[')><\"]*".format(
        "|".join(wordlist)
    )
    rematch = re.match(regex_password_acc, m_precise, re.IGNORECASE)

    return rematch.groups()[0]


def isPassword(read_file, read_file_lines, count_issue):
    wordlist = [
        "secret",
        "pgpassword",
        "password",
        "passwd",
        "pswrd",
        "pass",
        "pwd",
        "pw",
    ]

    # every string contains password in one line
    regex_password = ".*(?:{})[\s=(:'\"<>]+.*".format("|".join(wordlist))
    regex = re.compile(regex_password, re.IGNORECASE)

    clean_match = dict()
    for file, vals in read_file.items():
        match = regex.findall(vals)

        # assign issue if exists
        for m in match:
            m_precise = m.strip()

            rematch = getPasswordOnly(wordlist, m_precise)
            password_complexity = getPasswordComplexity(rematch)
            # print(password_complexity)

            if password_complexity >= 0.2:
                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = "Password"
                clean_match["issue " + str(count_issue)]["match"] = m_precise
                clean_match["issue " + str(count_issue)]["file"] = file

                # get line number
                first = read_file_lines[file].index(m_precise) + 1
                clean_match["issue " + str(count_issue)]["line"] = str(first)

                count_issue += 1

    return clean_match


def isCredentials(regex_creds, read_file, read_file_lines):
    count_issue = 1
    clean_match = dict()

    # find creds with regex
    for regex_type, values in regex_creds.items():
        regex = re.compile(values)

        for file, vals in read_file.items():
            match = regex.findall(vals)

            # assign issue if exists
            for m in match:
                m = m.strip()

                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = regex_type
                clean_match["issue " + str(count_issue)]["match"] = m
                clean_match["issue " + str(count_issue)]["file"] = file

                # get line number
                if (
                    "private" in regex_type.lower()
                    or "certificate" in regex_type.lower()
                    or "Google (GCP) Service-account" in regex_type
                ):
                    header = m.split("\n")[1]
                    first = (read_file_lines[file].index(header.strip()) + 1) - 1
                    last = first + len(m.split("\n")) - 1
                    clean_match["issue " + str(count_issue)][
                        "line"
                    ] = f"{first} - {last}"
                else:
                    first = index_containing_substring(read_file_lines[file], m) + 1
                    clean_match["issue " +
                                str(count_issue)]["line"] = str(first)

                count_issue += 1

    return clean_match, count_issue


def readModifiedFile(modified_files):
    read_file_lines = dict()
    read_file = dict()

    for file in modified_files:
        with open(file, "r") as f:
            data = f.readlines()
            data = [x.replace("\n", "").strip() for x in data]
            # data = [x for x in data if x != '']
            read_file_lines[file] = data

    for file in modified_files:
        with open(file, "r") as f:
            datas = f.read()
            read_file[file] = datas

    return read_file_lines, read_file


def getModifiedFile():
    # get staged file/folder
    diff_list = os.popen("git diff --name-only --cached").read()

    if diff_list == "":
        return None

    all_files = diff_list.strip().split("\n")

    file_ignore = (
        ".jpg", ".jpeg", ".png", ".gif", ".svg",
        ".mp4", ".mp3", ".webm", ".ttf", ".woff",
        ".eot", ".css", ".DS_Store", ".pdf",
    )

    # filtering
    filtered_file = list()
    for files in all_files:
        if not files.endswith(file_ignore):
            filtered_file.append(files)
    
    return filtered_file


def showTkinterWindow(final_res):
    class ScrollbarFrame(Frame):
        def __init__(self, parent, width, height, window_x, window_y, horizontal, **kwargs):
            Frame.__init__(self, parent, **kwargs)
            self.canvas_width  = width
            self.canvas_height = height
            self.window        = (window_x, window_y)

            # The Vertical Scrollbar, layout to the right
            vsb = Scrollbar(self, orient="vertical")
            vsb.pack(side=RIGHT, fill=Y)

            if horizontal:
                # The Horizontal Scrollbar, layout to the bottom
                hsb = Scrollbar(self, orient="horizontal")
                hsb.pack(side=BOTTOM, fill=X)

            # The Canvas which supports the Scrollbar Interface, layout to the left
            self.canvas = Canvas(self, highlightthickness=0, background="#ffffff",
                                    width=self.canvas_width, height=self.canvas_height
                                )
            self.canvas.pack(side="left", fill="both", expand=True)
            self.canvas.pack_propagate(0)

            # Bind the Scrollbar to the self.canvas Scrollbar Interface
            self.canvas.configure(yscrollcommand=vsb.set)
            vsb.configure(command=self.canvas.yview)

            if horizontal:
                self.canvas.configure(xscrollcommand=hsb.set)
                hsb.configure(command=self.canvas.xview)

            # The Frame to be scrolled, layout into the canvas
            # All widgets to be scrolled have to use this Frame as parent
            self.scrolled_frame = Frame(self.canvas, background=self.canvas.cget('bg'))
            self.canvas.create_window((self.window), window=self.scrolled_frame, anchor="nw")

            # Configures the scrollregion of the Canvas dynamically
            self.scrolled_frame.bind("<Configure>", self.on_configure)
            self.scrolled_frame.bind("<Enter>", self._bound_to_mousewheel)
            self.scrolled_frame.bind("<Leave>", self._unbound_to_mousewheel)
        
        def _bound_to_mousewheel(self, event):
            if platform.system() == "Linux":
                self.canvas.bind_all("<Button-4>", self._on_mousewheel)
                self.canvas.bind_all("<Button-5>", self._on_mousewheel)
            else:
                self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        def _unbound_to_mousewheel(self, event):
            if platform.system() == "Linux":
                self.canvas.unbind_all("<Button-4>")
                self.canvas.unbind_all("<Button-5>")
            else:
                self.canvas.unbind_all("<MouseWheel>")

        def _on_mousewheel(self, event):
            if platform.system() == "Darwin":
                delta = event.delta
            else:
                delta = event.delta//120
                
            self.canvas.yview_scroll(int(-1*(delta)), "units")

        def on_configure(self, event):
            """Set the scroll region to encompass the scrolled frame"""
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
 

    def initIssueDetails():
        global details_v_issue, details_v_type, details_v_file, details_v_line, details_v_match
        issue = "issue 1"

        details_v_issue = ttk.Label(details_content_a_val_content, text=f"  {issue.split()[-1]}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_issue.pack(pady=4)
        details_v_type = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['type']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_type.pack(pady=4)
        details_v_file = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['file']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_file.pack(pady=4)
        details_v_line = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['line']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_line.pack(pady=4)
        details_v_match = ttk.Label(sbf_details.scrolled_frame, text=f"{final_res[issue]['match']}", 
                                font=('Helvetica', 10), background="white", width=80, anchor='w')
        details_v_match.pack(pady=2, padx=6)


    def updateIssueDetails(issue):
        global details_v_issue, details_v_type, details_v_file, details_v_line, details_v_match
        details_v_issue.pack_forget()
        details_v_type.pack_forget()
        details_v_file.pack_forget()
        details_v_line.pack_forget()
        details_v_match.pack_forget()

        details_v_issue = ttk.Label(details_content_a_val_content, text=f"  {issue.split()[-1]}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_issue.pack(pady=4)
        details_v_type = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['type']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_type.pack(pady=4)
        details_v_file = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['file']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_file.pack(pady=4)
        details_v_line = ttk.Label(details_content_a_val_content, text=f"  {final_res[issue]['line']}", 
                                font=('Helvetica', 10), background="white", width=300, anchor='w')
        details_v_line.pack(pady=4)
        details_v_match = ttk.Label(sbf_details.scrolled_frame, text=f"{final_res[issue]['match']}", 
                                font=('Helvetica', 10), background="white", width=80, anchor='w')
        details_v_match.pack(pady=1, padx=6)


    def continueWithEncryption():

        def generateKey():
            enc_key = Fernet.generate_key()
            encryption_key_entry.delete(0, END)
            encryption_key_entry.insert(0, enc_key)


        def filesToEncrypt():
            files_to_encrypt = dict()
            issue_input = [x.strip() for x in issue_numbers_var.get().split(",")]
            for inputs in issue_input:
                if "issue {}".format(inputs) in final_res.keys():
                    file_name = final_res["issue {}".format(inputs)]["file"]
                    if file_name not in files_to_encrypt:
                        files_to_encrypt[file_name] = dict()
                    files_to_encrypt[file_name]["issue {}".format(inputs)] = dict()
                    files_to_encrypt[file_name]["issue {}".format(inputs)]["match"] = final_res["issue {}".format(inputs)]["match"]
                    files_to_encrypt[file_name]["issue {}".format(inputs)]["line"] = final_res["issue {}".format(inputs)]["line"]

            fernet = Fernet(encryption_key_entry.get())
            for file_name, issues in files_to_encrypt.items():
                with open(file_name, "r") as f:
                    lines = f.read()
                    for issue in issues:
                        encrypted_string = fernet.encrypt(issues[issue]["match"].encode())
                        lines = lines.replace(issues[issue]["match"], encrypted_string.decode())
                with open(file_name, "w") as f:
                    f.write(lines)

            popupWindow = Toplevel(root)
            popupWindow.title("Re-add and re-commit")
            popupWindow.resizable(False, False)

            tools_width = 400
            tools_height = 200
            center_width = int(screen_width/2) - int(tools_width/2)
            center_height = int(screen_height/2) - int(tools_height/2)
            popupWindow.geometry(f"{tools_width}x{tools_height}+{center_width}+{center_height}")

            popupWindow.grid_rowconfigure(0, minsize=35)
            popupWindow.grid_columnconfigure(0, weight=1)

            Label(popupWindow, text="Re-add the following files and re-commit", font=('Helvetica', 11, '')).grid(column=0, row=0, sticky=S)
            files_frame = Frame(popupWindow)
            files_frame.grid(column=0, row=1)

            files_content = Canvas(files_frame, background="white", width=200, height=100, bd=2, relief="groove")
            files_content.pack_propagate(0)
            files_content.pack(fill='both')

            files_content_frame = ttk.Frame(files_content, width=200, height=100)
            files_content_frame.pack(fill=BOTH, pady=4, padx=4)

            sbf_files = ScrollbarFrame(files_content_frame, 200, 100, 0, 0, horizontal=True)
            sbf_files.pack()
            sbf_files.scrolled_frame.grid_columnconfigure(0, minsize=200)

            i = 0
            for file_name, issues in files_to_encrypt.items():
                Label(sbf_files.scrolled_frame, text=file_name).grid(column=0, row=i, pady=2)
                i += 1
            # for i in range(10):
            #     Label(sbf_files.scrolled_frame, text=f"File {i}.txt").grid(column=0, row=i, pady=2)

            Button(popupWindow, text="Finish", width=30, 
                font=('Helvetica', 9, ''), background="#ccc", 
                command=closeRootWithExit1).grid(column=0, row=2, pady=10)


        selectIssueWindow = Toplevel(root)
        selectIssueWindow.title("Enter issue numbers")
        selectIssueWindow.resizable(False, False)

        tools_width = 500
        tools_height = 300
        center_width = int(screen_width/2) - int(tools_width/2)
        center_height = int(screen_height/2) - int(tools_height/2)
        selectIssueWindow.geometry(f"{tools_width}x{tools_height}+{center_width}+{center_height}")

        selectIssueWindow.grid_rowconfigure(0, minsize=35)
        selectIssueWindow.grid_columnconfigure(0, weight=1)

        Label(selectIssueWindow, text="Enter issue numbers to encrypt (ex: 1,2,5):", font=('Helvetica', 11, '')).grid(column=0, row=0, sticky=S)
        issue_numbers_var = StringVar()
        issue_numbers = Entry(selectIssueWindow, textvariable=issue_numbers_var, width=50, font=('Helvetica', 9, ''))
        issue_numbers.grid(column=0, row=1, pady=10)

        Label(selectIssueWindow, text="Encryption Key", font=('Helvetica', 11, '')).grid(column=0, row=2)
        encryption_key_entry = Entry(selectIssueWindow, width=50, font=('Helvetica', 9, ''))
        encryption_key_entry.grid(column=0, row=3, pady=10)

        Button(selectIssueWindow, text="Generate Key", width=40,
                font=('Helvetica', 9, ''), background="#ccc", 
                command=generateKey).grid(column=0, row=4, pady=10)
        Button(selectIssueWindow, text="Continue", width=40, 
                font=('Helvetica', 9, ''), background="#ccc", 
                command=filesToEncrypt).grid(column=0, row=5)
        Button(selectIssueWindow, text="Cancel", width=40, 
                font=('Helvetica', 9, ''), background="#ccc", 
                command=selectIssueWindow.destroy).grid(column=0, row=6, pady=10)


    def continueWithoutEncryption():
        confirmationWindow = Toplevel(root)
        confirmationWindow.title("Confirm")
        confirmationWindow.resizable(False, False)

        tools_width = 200
        tools_height = 100
        center_width = int(screen_width/2) - int(tools_width/2)
        center_height = int(screen_height/2) - int(tools_height/2)
        confirmationWindow.geometry(f"{tools_width}x{tools_height}+{center_width}+{center_height}")

        confirmationWindow.grid_rowconfigure(0, minsize=30)
        confirmationWindow.grid_columnconfigure(0, weight=1)
        
        Label(confirmationWindow, text="Are you sure?", width=25, font=('Helvetica', 11, '')).grid(column=0, row=0, sticky=NS)
        Button(confirmationWindow, text="Yes", width=25, 
                font=('Helvetica', 9, ''), background="#ccc", 
                command=closeRoot).grid(column=0, row=1)
        Button(confirmationWindow, text="No", width=25, 
                font=('Helvetica', 9, ''), background="#ccc", 
                command=confirmationWindow.destroy).grid(column=0, row=2, pady=10)

    
    def closeRootWithExit1():
        global exit_code
        exit_code = 1
        root.destroy()

    
    def closeRoot():
        global exit_code
        exit_code = 0
        root.destroy()


    root = Tk()
    # root.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1*(event.delta/120)), "units"))
    root.title("GitSanity")
    root.resizable(False, False)

    # Define Width & Height of Tools
    tools_width = 800
    tools_height = 650

    # Get Screen Width & Height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Get Screen Center Position
    center_width = int(screen_width/2) - int(tools_width/2)
    center_height = int(screen_height/2) - int(tools_height/2)

    root.geometry(f"{tools_width}x{tools_height}+{center_width}+{center_height}")

    # Create Canvas for Root
    root_container = ttk.Frame(root, borderwidth=1, relief='groove',
                            width=tools_width, height=tools_height)
    root_container.pack(fill='both', expand=True)

    # Create Container Issue
    issue_container = Frame(root_container, bd=1, relief='groove',
                                width=200, height=tools_height,
                                # padding='1 1 1 1'
                                )
    issue_container.pack(side=LEFT, fill='both')

    # Create Container Issue - Header Canvas
    issue_header = Canvas(issue_container, bg="white", width=170, height=25, bd=2)
    issue_header.pack()

    # Create Container Issue - Header Label
    issue_header_text = ttk.Label(issue_header, text="Issue", 
                                foreground="white", background="#555d50",
                                width=21, 
                                borderwidth=10, relief='groove',
                                font=("Helvetica", 11),
                                padding='5 5 9 5',
                                anchor=CENTER
                                )
    issue_header_text.pack()

    # Create Container Issue - Content Canvas
    issue_content = Canvas(issue_container, background="white", width=170, height=490, bd=2, relief="groove")
    issue_content.pack_propagate(0)
    issue_content.pack(fill='both')

    # Create Container Details - Content Canvas - Frame
    issue_content_frame = ttk.Frame(issue_content, width=170, height=490)
    issue_content_frame.pack(fill=BOTH, pady=4, padx=4)

    sbf_issue = ScrollbarFrame(issue_content_frame, 170, 490, 0, 5, False)
    sbf_issue.pack()
    sbf_issue.scrolled_frame.grid_columnconfigure(0, minsize=160)

    for i in range(len(final_res)):
        Button(sbf_issue.scrolled_frame, text=f"Issue {str(i+1)} \u003E",
                bd=0.5, font=('Helvetica', 9, ''),
                width=18, activebackground="#adadad",
                command=lambda i = i: updateIssueDetails(f"issue {str(i+1)}")
              ).grid(column=0, row=i+1, pady=5)

    # Create Container Issue - Total
    t_issue = len(final_res)
    issue_total = ttk.Label(issue_container, text=f"Total Issue: {str(t_issue)}",
                        font=('', 9),
                        width=23,
                        anchor=W
                        )
    issue_total.pack()

    # Create Container Details & Commit
    details_commit_container = ttk.Frame(root_container, borderwidth=1, relief='groove',
                                width=630, height=400,
                                padding='1 1 1 1'
                                )
    details_commit_container.pack(side=LEFT, fill='both')

    # Create Container Details - Header Canvas
    details_header = Canvas(details_commit_container, bg="white", width=630, height=25, bd=2)
    details_header.pack_propagate()
    details_header.pack(side=TOP)

    # Create Container Details - Header Label
    details_header_text = ttk.Label(details_header, text="Details", 
                                        foreground="white", background="#555d50",
                                        width=74, 
                                        borderwidth=10, relief='groove',
                                        font=("Helvetica", 11),
                                        padding='5 5 5 5',
                                        anchor=CENTER
                                        )
    details_header_text.pack()

    # Create Container Details - Content Canvas A
    details_content_a = Canvas(details_commit_container, width=630, height=150, bd=1, relief="flat")
    details_content_a.pack(fill='both')

    # Create Container Details - Content Canvas A - Frame Key
    details_content_a_key_frame = ttk.Frame(details_content_a, width=200, height=145)
    details_content_a_key_frame.pack(fill=BOTH, side=LEFT)

    # Create Container Details - Content Canvas A - Frame Key - Canvas & Label
    details_content_a_key_canvas = Canvas(details_content_a_key_frame, width=90, height=140)
    details_content_a_key_canvas.pack_propagate(0)
    details_content_a_key_canvas.pack(side=BOTTOM)

    for label in ("Issue", "Type", "File", "Line", "Match"):
        ttk.Label(details_content_a_key_canvas, text=label, font=('Helvetica', 10),
                  width=10, anchor='w').pack(pady=4)

    # Create Container Details - Content Canvas A - Frame Value
    details_content_a_val_frame = ttk.Frame(details_content_a, width=430, height=145)
    details_content_a_val_frame.pack(fill=BOTH)

    # Create Container Details - Content Canvas A - Frame Value - Canvas
    details_content_a_val_canvas = Canvas(details_content_a_val_frame, bg="white", bd=2, relief='groove', width=430, height=145)
    details_content_a_val_canvas.pack_propagate(0)
    details_content_a_val_canvas.pack()

    # Create Container Details - Content Canvas A - Frame Value - Canvas - Content
    global details_content_a_val_content
    details_content_a_val_content = Canvas(details_content_a_val_canvas, bg="white", highlightthickness=0, width=420, height=135)
    details_content_a_val_content.pack_propagate(0)
    details_content_a_val_content.pack(side=BOTTOM, padx=5, pady=8)

    # Create Container Details - Content Canvas B
    details_content_b = Canvas(details_commit_container, background="white", width=630, height=250, bd=2, relief="groove")
    details_content_b.pack_propagate(0)
    details_content_b.pack(fill='both')

    # Create Container Details - Content Canvas B - Frame
    details_content_b_key_frame = ttk.Frame(details_content_b, width=620, height=240)
    details_content_b_key_frame.pack(fill=BOTH, pady=10, padx=8)

    # Create Container Details - Content Canvas B - Content
    global sbf_details
    sbf_details = ScrollbarFrame(details_content_b_key_frame, 610, 240, 11, 4, True)
    sbf_details.pack()

    # Init Details Content
    initIssueDetails()

    # Create Container Commit
    commit_container = Frame(details_commit_container, borderwidth=1, relief='groove',
                                width=630, height=200, bg="white"
                                )
    commit_container.pack_propagate(0)
    commit_container.pack(side=BOTTOM, fill='both')

    # # Create Container Commit - Header Canvas
    commit_header = Canvas(commit_container, bg="white", width=630, height=25, bd=2)
    commit_header.pack()

    # Create Container Commit - Header Label
    commit_header_text = ttk.Label(commit_header, text="Commit Action", 
                                        foreground="white", background="#555d50",
                                        width=74, 
                                        borderwidth=10, relief='groove',
                                        font=("Helvetica", 11),
                                        padding='5 5 5 5',
                                        anchor=CENTER
                                        )
    commit_header_text.pack()

    # Create Container Commit - Content Canvas
    commit_content = Frame(commit_container, width=630, height=180, bd=1, bg="white")
    commit_content.pack_propagate()
    commit_content.pack()

    # Lanjut dari sini ...
    btn_encrypt = Button(commit_content, text="Continue with encryption", 
                            width=80, font=('Helvetica', 9, ''),
                            command=continueWithEncryption)
    btn_encrypt.grid(column=0, row=1, pady=10)
    btn_continue = Button(commit_content, text="Continue without encryption", 
                            width=80, font=('Helvetica', 9, ''), 
                            command=continueWithoutEncryption)
    btn_continue.grid(column=0, row=2)
    btn_cancel = Button(commit_content, text="Cancel", 
                            width=80, font=('Helvetica', 9, ''), 
                            command=closeRootWithExit1)
    btn_cancel.grid(column=0, row=3, pady=10)

    root.mainloop()


def main():
    global exit_code

    # list modified file from git diff
    modified_files = getModifiedFile()
    
    if modified_files is None:
        print("\nIt seems there is no file/directories in staged\n")
    
    else:
        # get list of regex
        stream = pkg_resources.resource_string(__name__, 'regex.json')
        # with open("regex.json") as f: regex_creds = json.load(f)
        regex_creds = json.loads(stream.decode())

        # read file per line and whole file
        read_file_lines, read_file = readModifiedFile(modified_files)

        # check creds such as api, token, private key, etc
        checkCredentials, count_issue = isCredentials(regex_creds, read_file, read_file_lines)

        # check creds such as password
        checkPassword = isPassword(read_file, read_file_lines, count_issue)

        # merge dict
        final_res = {**checkCredentials, **checkPassword}
        print("\n")

        # commit action
        if final_res:
            showTkinterWindow(final_res)
        else:
            exit_code = 0

    return exit_code

if __name__ == "__main__":
    # exit code for scan result
    exit_code = 0
    main()
