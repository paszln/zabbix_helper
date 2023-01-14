import tkinter.messagebox
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import *
from pyzabbix import ZabbixAPI
import csv
import configparser
import webbrowser

# GUI window create
root = Tk()
root.title("Zabbix Helper")
root.minsize(height=400, width=600)
root.maxsize(height=400, width=600)
root.resizable(False,False)

# to read and write a file in pc
config = configparser.ConfigParser()

# list for elements that will be clear in future
sequence = []

# get all host from zabbix
def gethost(username, password, api):

    # Setup Zabbix API connection
    zapi = ZabbixAPI(api)

    # Login to the Zabbix API
    zapi.login(username, password)

    hosts = zapi.host.get(output="extend")
    return hosts

# about this program in heading menu button
def info():
    tkinter.messagebox.showinfo("About", "Version - Beta 0.0.1")

# exit button in heading menu
def exitprogram():
    closeconfirm = tkinter.messagebox.askquestion("Exit", "Do you want to exit a program?")

    if closeconfirm == "yes":
        root.destroy()

# Heading menu
mymenu = Menu()
root.config(menu=mymenu)
mymenu.add_cascade(label="About", command=info)
mymenu.add_cascade(label="Exit", command=exitprogram)

# open a file expoler to select .csv file
def choosefile():
    fileopen = askopenfilename(filetypes = [("File CSV","*.csv")])

    zapi = ZabbixAPI(config['DEFAULT']['api'])
    zapi.login(user=config['DEFAULT']['username'], password=config['DEFAULT']['password'])

    arq = csv.reader(open(fileopen))

    linhas = sum(1 for linha in arq)

    f = csv.reader(open(fileopen))

    try:
        for [hostname, ip, type] in f:
            hostcriado = zapi.host.create(
                host=hostname,
                status=1,
                interfaces=[{
                    "type": type,
                    "main": "1",
                    "useip": 1,
                    "ip": ip,
                    "dns": "",
                    "port": 10050
                }],
                groups=[{
                    "groupid": 2
                }],
                templates=[{
                    "templateid": 10001
                }]

            )
    except ValueError as e:
        f = csv.reader(open(fileopen), delimiter=';')

        for [hostname, ip, type] in f:
            hostcriado = zapi.host.create(
                host=hostname,
                status=1,
                interfaces=[{
                    "type": type,
                    "main": "1",
                    "useip": 1,
                    "ip": ip,
                    "dns": "",
                    "port": 10050
                }],
                groups=[{
                    "groupid": 2
                }],
                templates=[{
                    "templateid": 10001
                }]

            )

# clear screen element when sign in or sign out
def clearscreen():
    for x in sequence:
        x.destroy()

# Main screen when run this program
def tab1():

    # Save sign in data to file
    def savelogin():

        config.read('config.ini')
        config['DEFAULT']['username'] = username.get()  # update
        config['DEFAULT']['password'] = password.get()  # update
        config['DEFAULT']['api'] = api.get()  # update
        config['DEFAULT']['no_verify'] = 'true'  # update

        with open('config.ini', 'w') as configfile:  # save
            config.write(configfile)

    # Second screen when hit sign in button
    def tab2():
        frame = ttk.Frame(root)
        canvas = Canvas(frame, borderwidth=0, background="#ffffff")
        canvas.config(width=175, height=240)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        clearscreen()
        savelogin()
        frame.pack()

        # update all host list after import .csv file
        def render():
            hosts = gethost(username.get(), password.get(), api.get())
            for host in hosts:
                row = 0
                labelhostname = Label(scrollable_frame, text=host["host"], borderwidth=1, relief="solid", width=25,
                                      height=2)
                sequence.append(labelhostname)
                labelhostname.pack()

                if host["status"] == '0':
                    ava = Label(scrollable_frame, text="Available", bg="#34af67", fg="white", borderwidth=1,
                                relief="solid", width=25, height=2)
                    sequence.append(ava)
                    ava.pack(pady=(0, 10))
                else:
                    notava = Label(scrollable_frame, text="Unavailable", bg="#e33734", fg="white", borderwidth=1,
                                   relief="solid", width=25, height=2)
                    sequence.append(notava)
                    notava.pack(pady=(0, 10))

                row += 1
                print(host)

        # clear all element after hit sign out button and send user back to main screen
        def back():
            frame.destroy()
            clearscreen()
            tab1()

        # open zabbix webpage in new tab
        def link():
            webbrowser.open_new(api.get())

        # clear all element in list
        sequence.clear()

        # label and button in 2nd screen GUI
        label5 = Label(root, text='Hosts & Status', font=('Helvetica', 16))
        sequence.append(label5)
        label5.pack()
        button3 = Button(root, text='Import (CSV Only)', command=lambda: [choosefile(), render()], bg="#0275b8", fg="white", activebackground="#0275b8", width=15, font=('Helvetica', 10))
        sequence.append(button3)
        button3.pack(pady=(10,0))
        button4 = Button(root, text='Edit', command=link, bg="#0275b8", fg="white", activebackground="#0275b8", width=15, font=('Helvetica', 10))
        sequence.append(button4)
        button4.pack(pady=(5, 20))

        # pack all element in 2nd screen to GUI window
        frame.pack()
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        button2 = Button(root, text='Sign out', command=back, bg="#EE0000", fg="white", activebackground="#EE0000")
        sequence.append(button2)
        button2.pack()

    # label button and entry element in main screen GUI and pack it
    label1=Label(text="ZABBIX", font=('Aerial', 30), bg="#D30000", fg="white")
    sequence.append(label1)
    label1.pack(pady=20)
    label2 = Label(root, text="Username", font=('Helvetica', 16), anchor='w', width=20)
    sequence.append(label2)
    label2.pack(pady=(12, 0))
    username = StringVar()
    entry1 = Entry(root, font=(None, 16), textvariable=username)
    sequence.append(entry1)
    entry1.pack()
    label3 = Label(root, text="Password", font=('Helvetica', 16), anchor='w', width=20)
    sequence.append(label3)
    label3.pack(pady=(12, 0))
    password = StringVar()
    entry2 = Entry(root, font=(None, 16), textvariable=password, show="*")
    sequence.append(entry2)
    entry2.pack()
    label4 = Label(root, text="IP Address", font=('Helvetica', 16), anchor='w', width=20)
    sequence.append(label4)
    label4.pack(pady=(12, 0))
    api = StringVar()
    entry3 = Entry(root, font=(None, 16), textvariable=api)
    sequence.append(entry3)
    entry3.pack()
    button1 = Button(root, text="Sign in", command=tab2, width=20, font=('Helvetica', 16), bg="#0174B7",
                           fg="white", activebackground="#0174B7")
    sequence.append(button1)
    button1.pack(pady=(24, 0))

tab1()
root.mainloop()