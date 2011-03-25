# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'secondAttempt.ui'
#
# Created by: PyQt4 UI code generator 4.7.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
from PyQt4.QtNetwork import QTcpServer, QTcpSocket, QHostAddress
from PyQt4.Qt import QMessageBox, QString
from PyQt4.QtCore import QDataStream
import net
import socket

SIZEOF_UINT16 = 2

class TcpServer(QTcpServer):
    def __init__(self):
        super(TcpServer, self).__init__()

    def incomingConnection(self, socketId):
        socket = Socket(self)
        socket.setSocketDescriptor(socketId)

        # create socket, connect signal to signal GUI is listening for
        self.connect(socket, QtCore.SIGNAL("socketReceived(QString)"), QtCore.SIGNAL("messageReceived(QString)"))

class Socket(QTcpSocket):
    def __init__(self, parent=None):
        super(Socket, self).__init__(parent)
        self.connect(self, QtCore.SIGNAL("readyRead()"), self.readRequest)
        self.nextBlockSize = 0

    # read data sent over localhost TCP
    def readRequest(self):
        stream = QDataStream(self)
        stream.setVersion(QDataStream.Qt_4_2)

        # make sure enough/all bytes are present
        if self.nextBlockSize == 0:
            if self.bytesAvailable() < SIZEOF_UINT16:
                return
            self.nextBlockSize = stream.readUInt16()
        if self.bytesAvailable() < self.nextBlockSize:
            return

        action = QString()
        stream >> action
        uni_action = unicode(action)

        # populate up to GUI
        self.emit(QtCore.SIGNAL("socketReceived(QString)"), QString(uni_action))

class Ui_DissentWindow(object):
    def setupUi(self, DissentWindow):
        self.tcpServer = TcpServer()
        if not self.tcpServer.listen(QHostAddress("127.0.0.1"), 20000):
            print self.tcpServer.errorString()
            return

        # register GUI to listen for TCP signals (to display on debug screen)
        QtCore.QObject.connect(self.tcpServer,QtCore.SIGNAL("messageReceived(QString)"), self.displayMessage)

        self.net = net.Net()

        DissentWindow.setObjectName("DissentWindow")
        DissentWindow.resize(835, 576)
        self.centralwidget = QtGui.QWidget(DissentWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(630, 10, 191, 531))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.horizontalLayoutWidget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_3 = QtGui.QLabel(self.horizontalLayoutWidget)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_3.addWidget(self.label_3)
        self.nodeList = QtGui.QListWidget(self.horizontalLayoutWidget)
        self.nodeList.setObjectName("nodeList")
        self.add_nodes()
        self.verticalLayout_3.addWidget(self.nodeList)
        self.bootNodeButton = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.bootNodeButton.setObjectName("bootNodeButton")
        self.verticalLayout_3.addWidget(self.bootNodeButton)
        self.waitButton = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.waitButton.setObjectName("waitButton")
        self.verticalLayout_3.addWidget(self.waitButton)
        self.verticalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 10, 361, 51))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.horizontalLayout_6 = QtGui.QHBoxLayout(self.verticalLayoutWidget)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.inviteButton = QtGui.QPushButton(self.verticalLayoutWidget)
        self.inviteButton.setObjectName("inviteButton")
        self.horizontalLayout_6.addWidget(self.inviteButton)
        self.inviteAddress = QtGui.QLineEdit(self.verticalLayoutWidget)
        self.inviteAddress.setObjectName("inviteAddress")
        self.horizontalLayout_6.addWidget(self.inviteAddress)
        self.horizontalLayoutWidget_3 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_3.setGeometry(QtCore.QRect(10, 60, 361, 51))
        self.horizontalLayoutWidget_3.setObjectName("horizontalLayoutWidget_3")
        self.horizontalLayout_7 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_3)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.label_5 = QtGui.QLabel(self.horizontalLayoutWidget_3)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout_7.addWidget(self.label_5)
        self.filePath = QtGui.QLineEdit(self.horizontalLayoutWidget_3)
        self.filePath.setObjectName("filePath")
        self.horizontalLayout_7.addWidget(self.filePath)
        self.horizontalLayoutWidget_4 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_4.setGeometry(QtCore.QRect(10, 110, 361, 51))
        self.horizontalLayoutWidget_4.setObjectName("horizontalLayoutWidget_4")
        self.horizontalLayout_8 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_4)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.dropOutButton = QtGui.QPushButton(self.horizontalLayoutWidget_4)
        self.dropOutButton.setObjectName("dropOutButton")
        self.horizontalLayout_8.addWidget(self.dropOutButton)
        self.verticalLayoutWidget_2 = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(380, 10, 241, 531))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label = QtGui.QLabel(self.verticalLayoutWidget_2)
        self.label.setObjectName("label")
        self.verticalLayout_2.addWidget(self.label)
        self.privateKeyField = QtGui.QTextEdit(self.verticalLayoutWidget_2)
        self.privateKeyField.setObjectName("privateKeyField")
        self.privateKeyField.setReadOnly(True)
        self.verticalLayout_2.addWidget(self.privateKeyField)
        self.label_2 = QtGui.QLabel(self.verticalLayoutWidget_2)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_2.addWidget(self.label_2)
        self.publicKeyField = QtGui.QTextEdit(self.verticalLayoutWidget_2)
        self.publicKeyField.setObjectName("publicKeyField")
        self.publicKeyField.setReadOnly(True)
        self.verticalLayout_2.addWidget(self.publicKeyField)
        self.verticalLayoutWidget_3 = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(10, 160, 361, 381))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_4 = QtGui.QLabel(self.verticalLayoutWidget_3)
        self.label_4.setObjectName("label_4")
        self.verticalLayout_4.addWidget(self.label_4)
        self.debugField = QtGui.QTextEdit(self.verticalLayoutWidget_3)
        self.debugField.setObjectName("debugField")
        self.verticalLayout_4.addWidget(self.debugField)
        DissentWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(DissentWindow)
        self.statusbar.setObjectName("statusbar")
        DissentWindow.setStatusBar(self.statusbar)

        self.retranslateUi(DissentWindow)

        # make this button temporarily force debug messages for testing
        QtCore.QObject.connect(self.waitButton, QtCore.SIGNAL("clicked()"), self.net.testMessage)
        QtCore.QObject.connect(self.inviteButton, QtCore.SIGNAL("clicked()"), self.invitePressed)
        QtCore.QMetaObject.connectSlotsByName(DissentWindow)
        self.display_keys()

    def retranslateUi(self, DissentWindow):
        DissentWindow.setWindowTitle(QtGui.QApplication.translate("DissentWindow", "µDissent", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("DissentWindow", "Nodes in my network", None, QtGui.QApplication.UnicodeUTF8))
        self.bootNodeButton.setText(QtGui.QApplication.translate("DissentWindow", "Boot Selected Node", None, QtGui.QApplication.UnicodeUTF8))
        self.waitButton.setText(QtGui.QApplication.translate("DissentWindow", "Wait", None, QtGui.QApplication.UnicodeUTF8))
        self.inviteButton.setText(QtGui.QApplication.translate("DissentWindow", "Invite", None, QtGui.QApplication.UnicodeUTF8))
        self.inviteAddress.setText(QtGui.QApplication.translate("DissentWindow", "IP:PORT", None, QtGui.QApplication.UnicodeUTF8))
        self.label_5.setText(QtGui.QApplication.translate("DissentWindow", "Path to File:", None, QtGui.QApplication.UnicodeUTF8))
        self.filePath.setText(QtGui.QApplication.translate("DissentWindow", "Absolute Path", None, QtGui.QApplication.UnicodeUTF8))
        self.dropOutButton.setText(QtGui.QApplication.translate("DissentWindow", "Drop out of Dissent", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("DissentWindow", "My Private Key", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("DissentWindow", "My Public Key", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("DissentWindow", "Debug", None, QtGui.QApplication.UnicodeUTF8))

    # display any messages populated up to GUI
    def displayMessage(self, msg):
        self.debugField.append(msg)

    # show keys on screen
    def display_keys(self):
        self.publicKeyField.setPlainText(self.net.public_key_string())
        self.privateKeyField.setPlainText(self.net.private_key_string())

    # add peers from net class to list
    def add_nodes(self):
        peers = self.net.nodes
        for peer in peers:
            self.nodeList.addItem(QString(socket.gethostbyaddr(peer[0])[0] + ":" + str(peer[1])))
    
    def invitePressed(self):
        peer = str(self.inviteAddress.text())
        self.net.invite_peer(peer)
