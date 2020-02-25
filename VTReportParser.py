import json
import hashlib
from virustotal_python import Virustotal
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image

vt = Virustotal("<<INSERT API KEY HERE>>")


def main():
    menu()


def menu():
    menu = Tk()
    menu.title('Virus Total Report Parser')
    image=Image.open("VT.png")
    image= image.resize((450,250), Image.ANTIALIAS)
    menu.resizable(False, False)
    img = ImageTk.PhotoImage(image)
    pane = Label(menu, image=img)
    pane.place(x=10, y=-30)
    sig=Label(menu, text="By: Sean Guthrie \ B00073216")
    sig.place(x=40, y=460)

    ver=Label(menu, text="Version: 2.0")
    ver.place(x=360, y=460)
    menu.geometry("500x500+10+20")

    onelabel = Label(menu, text="Upload a File")
    one = Button(menu, text="Upload File", command=lambda: ScanF(FStr))
    onelabel.place(x=100, y=200)
    one.place(x=300, y=200)

    twolabel = Label(menu, text="Get File Report")
    two = Button(menu, text="Get file report", command=lambda: FileR())
    twolabel.place(x=100, y=235)
    two.place(x=300, y=235)

    threelabel = Label(menu, text="Upload URL")
    three = Button(menu, text="Upload Url", command=lambda: ScanURL(URLStr))
    threelabel.place(x=100, y=270)
    three.place(x=300, y=270)

    fourlabel = Label(menu, text="Get URL Report")
    four = Button(menu, text="Get URL Report", command=lambda: URLR())
    fourlabel.place(x=100, y=305)
    four.place(x=300, y=305)
    fivelabel = Label(menu, text="Malware Hash Report")
    five = Button(menu, text="Malware Hash", command=lambda: RepStat())
    fivelabel.place(x=100, y=340)
    five.place(x=300, y=340)

    FStr = StringVar()

    filelab=Label(menu, text="File: ")
    filefile=Label(menu,textvariable=FStr)
    filelab.place(x=70, y=400)
    filefile.place(x=100, y=400)

    URLStr = StringVar()

    URLlab=Label(menu, text="URL: ")
    URLFile=Label(menu,textvariable=URLStr)
    URLlab.place(x=70, y=415)
    URLFile.place(x=100, y=415)


    menu.mainloop()


def ScanF(FStr):
    def rep2():
        def close():
            f.destroy()

        ans=json.dumps(sendF, indent=3)

        f = Tk()
        f.title('File Report')
        lbl2= Label(f, text="File Sent Response")
        lbl2.place(x=300, y=20)
        f.resizable(False, False)


        scroll = Scrollbar(f)
        scroll.pack(side=RIGHT, fill=Y)

        txt = Text(f, width=72, height=12, yscrollcommand=scroll.set)
        txt.place(x=50, y=50)

        txt.insert(INSERT,ans)

        save = Button(f, text="Save File", command= filesave)
        save.place(x=220, y=260)

        quit = Button(f, text="Close", command=close)
        quit.place(x=400, y=260)


        scroll.config(command=txt.yview)
        f.geometry("700x300+10+20")
        f.mainloop()

    global fplace
    root = Tk()
    root.resizable(False, False)
    root.lift()
    root.filename = filedialog.askopenfilename(initialdir="/", title="Select File", filetypes=(()))
    fplace =root.filename
    FStr.set(fplace)
    sendF = vt.file_scan(fplace)
    print(sendF)
    root.destroy()
    rep2()


def FileR():

    def close():
        root.destroy()

    global ans
    with open(fplace,"rb") as file:
        bytes=file.read()
        shaha = hashlib.sha256(bytes).hexdigest();
    resp = vt.file_report([shaha])
    ans= json.dumps(resp, indent=4)
    root = Tk()
    root.resizable(False, False)
    root.title('File Report')
    lbl = Label(root, text=fplace)
    lbl2= Label(root, text="File: ")
    lbl.place(x=70, y=20)
    lbl2.place(x=50, y=20)
    scroll = Scrollbar(root)
    scroll.pack(side=RIGHT, fill=Y)

    txt = Text(root, width=72, height=37, yscrollcommand=scroll.set)
    txt.place(x=50, y=50)

    txt.insert(INSERT,ans)
    save = Button(root, text="Save File", command= filesave)
    save.place(x=200, y=650)

    quit = Button(root, text="Exit", command=close)
    quit.place(x=400, y=650)

    scroll.config(command=txt.yview)
    root.geometry("700x700+10+20")
    root.mainloop()



def ScanURL(URLStr):
    root = Tk()
    root.resizable(False, False)
    def rep3():
        def close():
            f.destroy()

        res= vt.url_scan([url])
        ans=json.dumps(res, indent=3)

        f = Tk()
        f.title('URL Sent Response')
        lbl2= Label(f, text="URL Sent Response")
        lbl2.place(x=300, y=20)
        f.resizable(False, False)


        scroll = Scrollbar(f)
        scroll.pack(side=RIGHT, fill=Y)

        txt = Text(f, width=72, height=12, yscrollcommand=scroll.set)
        txt.place(x=50, y=50)

        txt.insert(INSERT,ans)

        save = Button(f, text="Save File", command= filesave)
        save.place(x=220, y=260)

        quit = Button(f, text="Close", command=close)
        quit.place(x=400, y=260)


        scroll.config(command=txt.yview)
        f.geometry("700x300+10+20")
        f.mainloop()


    def insert():
        global url
        url=text.get()
        URLStr.set(url)
        root.destroy()
        rep3()


    root.lift()
    root.title('Enter URL')
    root.geometry("200x100+10+20")

    lbl = Label(root, text="Enter URL")
    lbl.place(x=50, y=100)
    lbl.pack()

    text = Entry(root,textvariable="text")
    text.bind("<Return>", lambda event: insert())
    text.pack()

    but = Button(root, text="Enter", command=lambda: insert())

    but.place(x=80, y=170)
    but.pack()
    root.mainloop()
    respon = vt.url_scan([url])


def URLR():

    def close():
        root.destroy()

    global ans
    resp = vt.url_report([url])
    ans=json.dumps(resp, indent=4)


    root = Tk()
    root.title('URL Report')
    root.resizable(False, False)

    lbl = Label(root, text=[url])
    lbl2= Label(root, text="URL: ")
    lbl.place(x=70, y=20)
    lbl2.place(x=50, y=20)

    scroll = Scrollbar(root)
    scroll.pack(side=RIGHT, fill=Y)

    txt = Text(root, width=72, height=37, yscrollcommand=scroll.set)
    txt.place(x=50, y=50)

    txt.insert(INSERT,ans)

    save = Button(root, text="Save File", command= filesave)
    save.place(x=200, y=650)

    quit = Button(root, text="Exit", command=close)
    quit.place(x=400, y=650)


    scroll.config(command=txt.yview)
    root.geometry("700x700+10+20")
    root.mainloop()


def RepStat():
    root = Tk()
    root.resizable(False, False)

    def insert():
        global mal
        mal=text.get()
        root.destroy()
        rep()
    def rep():
        def close():
            root.destroy()

        global ans
        resp = vt.file_report([mal])
        ans=json.dumps(resp, indent=4)

        root = Tk()
        root.title('Malware Report')
        root.resizable(False, False)
        lbl = Label(root, text=[mal])
        lbl2= Label(root, text="Malware SHA256: ")
        lbl.place(x=70, y=20)
        lbl2.place(x=50, y=20)

        scroll = Scrollbar(root)
        scroll.pack(side=RIGHT, fill=Y)

        txt = Text(root, width=72, height=37, yscrollcommand=scroll.set)
        txt.place(x=50, y=50)

        txt.insert(INSERT,ans)

        save = Button(root, text="Save File", command= filesave)
        save.place(x=200, y=650)

        quit = Button(root, text="Exit", command=close)
        quit.place(x=400, y=650)


        scroll.config(command=txt.yview)
        root.geometry("700x700+10+20")
        root.mainloop()

    root.lift()
    root.title('Enter Malware SHA256')
    root.geometry("200x100+10+20")

    lbl = Label(root, text="Enter Malware SHA256")
    lbl.place(x=50, y=100)
    lbl.pack()

    text = Entry(root,textvariable="text")
    text.bind("<Return>", lambda event: insert())
    text.pack()

    but = Button(root, text="Enter", command=lambda: insert())

    but.place(x=80, y=170)
    but.pack()
    root.mainloop()



def filesave():
    save = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
    if save is None:
        return
    save.write(ans)
    save.close()
main()
