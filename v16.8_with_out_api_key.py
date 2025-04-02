# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList
from java.util.regex import Pattern
from javax.swing import JPanel, JLabel, JTextArea, JScrollPane, JButton, JFileChooser, GroupLayout, JTabbedPane, JCheckBox, JRadioButton, ButtonGroup, JTextField, JDialog, JSeparator
from java.awt import Font, Color, Dimension, BorderLayout
from java.awt.event import ActionEvent
from threading import Thread, Lock
from java.util.concurrent import Executors  # برای Thread Pool
import binascii
import base64
import re
import json
from burp import IScanIssue
from javax.swing import DefaultListModel, JList, JOptionPane


ENABLE_GENERAL_HTTP_SCANNING = False  # پیش‌فرض: فقط JS/JSON اسکن می‌شه
# تنظیمات اولیه (به‌صورت متغیرهای جهانی)
JSExclusionList = ['jquery', 'google-analytics', 'gpt.js']
SENSITIVE_PATTERNS = {

    'Stripe API Keys': r"(?:const|var|let)\s+S\d+\s*=\s*'(pk_live_|sk_live_).+';",
    'Stripe API Keys': r"(?:const|var|let)\s+S\d+\s*=\s*'(pk_live_?|sk_live_?).+';",
    'Variable Definition with Long Value': r'(var|let|const)\s+(\w+\$?\d*)\s*=\s*"([A-Za-z0-9_-]{20,})"',
    'Stripe Key': r'(sk_liveـ|pk_live)_[0-9a-zA-Z]{24}',


}
API_PATTERN_STRINGS = [
    r'/api/[a-zA-Z0-9_\-/]+',
    r'/v\d+/api/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+/api/v\d+/[a-zA-Z0-9_\-/]+',
    r'/api-v\d+/[a-zA-Z0-9_\-/]+',
    r'(?:/rest|/rest-api)/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+-rest/[a-zA-Z0-9_\-/]+',
    r'/v\d+/[a-zA-Z0-9_\-/]+',
    r'/version\d+/[a-zA-Z0-9_\-/]+',
    r'/legacy-v\d+/[a-zA-Z0-9_\-/]+',
    r'/v[a-zA-Z0-9]+/.*',
    r'/service/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+-service/[a-zA-Z0-9_\-/]+',
    r'/service-api/[a-zA-Z0-9_\-/]+',
    r'/graphql(?:\?.*)?',
    r'/[a-zA-Z0-9_\-]+-graphql(?:\?.*)?',
    r'(?:/ws|wss://)[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+(?:-ws|-wss)/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+/socket/[a-zA-Z0-9_\-/]+',
    r'(?:/rpc|/json-rpc)/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+(?:-rpc|-json-rpc)/[a-zA-Z0-9_\-/]+',
    r'/soap/[a-zA-Z0-9_\-/]+',
    r'/[a-zA-Z0-9_\-]+-soap/[a-zA-Z0-9_\-/]+',
    r'/admin(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/administrator(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/console(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/panel(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/backend(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/system(?:/api)?/[a-zA-Z0-9_\-/]+',
    r'/auth/[a-zA-Z0-9_\-/]+',
    r'/authentication/[a-zA-Z0-9_\-/]+',
    r'/login(?:/[a-zA-Z0-9_\-]+)?',
    r'/logout(?:/[a-zA-Z0-9_\-]+)?',
    r'/signup(?:/[a-zA-Z0-9_\-]+)?',
    r'/register(?:/[a-zA-Z0-9_\-]+)?',
    r'/oauth(?:/[a-zA-Z0-9_\-]+)?',
    r'/sso(?:/[a-zA-Z0-9_\-]+)?',
    r'/token(?:/[a-zA-Z0-9_\-]+)?',
    r'/user(?:s)?/[a-zA-Z0-9_\-/]+',
    r'/profile(?:/[a-zA-Z0-9_\-]+)?',
    r'/account(?:/[a-zA-Z0-9_\-]+)?',
    r'/customer(?:s)?/[a-zA-Z0-9_\-/]+',
    r'/member(?:s)?/[a-zA-Z0-9_\-/]+',
    r'/client(?:s)?/[a-zA-Z0-9_\-/]+',
    r'/swagger(?:-ui)?(?:/[a-zA-Z0-9_\-]+)?',
    r'/api-docs(?:/[a-zA-Z0-9_\-]+)?',
    r'/openapi(?:/[a-zA-Z0-9_\-]+)?',
    r'/redoc(?:/[a-zA-Z0-9_\-]+)?',
    r'/(?:api-|)documentation(?:/[a-zA-Z0-9_\-]+)?',
    r'/(?:api-|)reference(?:/[a-zA-Z0-9_\-]+)?',
    r'/[a-zA-Z0-9_]+-api',
    r'/endpoints',
    r'/gateway',
    r'/entrypoint',
    r'/[a-zA-Z0-9_]+/v\d+',
    r'/[a-zA-Z0-9_]+\.asmx(?:/[a-zA-Z0-9_\-]+)?',
    r'/[a-zA-Z0-9_]+\.cfc(?:/[a-zA-Z0-9_\-]+)?',
    r'/[a-zA-Z0-9_]+\.jhtml(?:/[a-zA-Z0-9_\-]+)?',
    r'/[a-zA-Z0-9_]+\.action(?:/[a-zA-Z0-9_\-]+)?',
    r'/internal(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/private(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/protected(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/restricted(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/hidden(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/external(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/public(?:-api)?/[a-zA-Z0-9_\-/]+',
    r'/mobile(?:/v\d+)?/[a-zA-Z0-9_\-/]+'
]
API_PATTERNS = [re.compile(pattern) for pattern in API_PATTERN_STRINGS]

VULN_PATTERNS = {
    'XSS': [r'<script>', r'alert\(', r'onerror='],
    'SQLi': [r'\bUNION\b.*\bSELECT\b', r'\bDROP\b.*\bTABLE\b', r'\bOR\b\s*\d+\s*=\s*\d+']
}
ENABLED_LOGS = ['Sensitive Data', 'API Endpoints', 'Comments', 'General Links']
OUTPUT_FORMAT = 'Plain Text'
FILE_EXTENSIONS = ['js', 'json']
THREAD_POOL_SIZE = 4  # متغیر برای تعداد تردها

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSJSONFinder")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)

        # Initialize JTextAreas
        self.commentsTxtArea = JTextArea()
        self.apiEndpointsTxtArea = JTextArea()
        self.sensitiveDataTxtArea = JTextArea()
        self.generalOutputTxtArea = JTextArea()

        # Thread Pool با تعداد تردهای قابل تنظیم
        self.threadPool = Executors.newFixedThreadPool(THREAD_POOL_SIZE)

        self.initUI()
        self.callbacks.addSuiteTab(self)
        self.logLock = Lock()
        self.log("Burp JS/JSON Finder loaded.\nReady to scan for links in JS and JSON files.")

    def initUI(self):
        self.tabbedPane = JTabbedPane()

        # تب‌های خروجی
        tabs = [
            {"name": "General Output", "label": "General Output:", "textArea": self.generalOutputTxtArea},
            {"name": "API Endpoints", "label": "Extracted API Endpoints:", "textArea": self.apiEndpointsTxtArea},
            {"name": "Sensitive Data", "label": "Extracted Sensitive Data:", "textArea": self.sensitiveDataTxtArea},
            {"name": "Comments", "label": "Extracted Comments:", "textArea": self.commentsTxtArea}
        ]

        for tab in tabs:
            tabPanel = JPanel()
            label = JLabel(tab["label"])
            label.setFont(Font("Tahoma", Font.BOLD, 14))
            label.setForeground(Color(255, 102, 52))
            textArea = tab["textArea"]
            textArea.setFont(Font("Consolas", Font.PLAIN, 12))
            
            # تنظیمات خاص برای تب Extracted Comments
            if tab["name"] == "Comments":
                textArea.setLineWrap(False)  # غیرفعال کردن شکستن خودکار خطوط
                textArea.setWrapStyleWord(False)
            else:
                textArea.setLineWrap(True)
                textArea.setEditable(False)

            scrollPane = JScrollPane(textArea)
            # اضافه کردن اسکرول افقی برای تب Extracted Comments
            if tab["name"] == "Comments":
                scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS)  # همیشه اسکرول افقی نشون داده بشه
                scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)  # اسکرول عمودی در صورت نیاز
            clearButton = JButton("Clear", actionPerformed=lambda e, ta=textArea: ta.setText(""))
            exportButton = JButton("Export", actionPerformed=lambda e, ta=textArea: self.exportText(ta))

            layout = GroupLayout(tabPanel)
            tabPanel.setLayout(layout)
            layout.setAutoCreateGaps(True)
            layout.setAutoCreateContainerGaps(True)
            layout.setHorizontalGroup(
                layout.createParallelGroup()
                    .addComponent(label)
                    .addComponent(scrollPane)
                    .addComponent(clearButton)
                    .addComponent(exportButton)
            )
            layout.setVerticalGroup(
                layout.createSequentialGroup()
                    .addComponent(label)
                    .addComponent(scrollPane)
                    .addComponent(clearButton)
                    .addComponent(exportButton)
            )
            self.tabbedPane.addTab(tab["name"], tabPanel)

        # تب Settings
        settingsPanel = JPanel()
        settingsLayout = GroupLayout(settingsPanel)
        settingsPanel.setLayout(settingsLayout)
        settingsLayout.setAutoCreateGaps(True)
        settingsLayout.setAutoCreateContainerGaps(True)

        # جداکننده برای گروه‌ها
        separator = JSeparator()

        # گروه ۱: API Patterns
        apiLabel = JLabel("API Patterns")
        apiLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        apiLabel.setForeground(Color(255, 102, 52))
        self.apiListModel = DefaultListModel()
        for pattern in API_PATTERN_STRINGS:
            self.apiListModel.addElement(pattern)
        self.apiList = JList(self.apiListModel)
        apiScrollPane = JScrollPane(self.apiList)
        apiAddButton = JButton("Add", actionPerformed=lambda e: self.addItem(self.apiListModel))
        apiAddMultipleButton = JButton("Add Multiple", actionPerformed=lambda e: self.addMultipleItems(self.apiListModel, "API Patterns", True))
        apiEditButton = JButton("Edit", actionPerformed=lambda e: self.editItem(self.apiList, self.apiListModel))
        apiRemoveButton = JButton("Remove", actionPerformed=lambda e: self.removeItem(self.apiList, self.apiListModel))

        # گروه ۲: Vulnerability Patterns
        vulnLabel = JLabel("Vuln Patterns")
        vulnLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        vulnLabel.setForeground(Color(255, 102, 52))
        self.vulnListModel = DefaultListModel()
        for vuln_type, patterns in VULN_PATTERNS.items():
            for pattern in patterns:
                self.vulnListModel.addElement("{}: {}".format(vuln_type, pattern))
        self.vulnList = JList(self.vulnListModel)
        vulnScrollPane = JScrollPane(self.vulnList)
        vulnAddButton = JButton("Add", actionPerformed=lambda e: self.addVulnItem(self.vulnListModel))
        vulnAddMultipleButton = JButton("Add Multiple", actionPerformed=lambda e: self.addMultipleVulnItems(self.vulnListModel, "Vuln Patterns"))
        vulnEditButton = JButton("Edit", actionPerformed=lambda e: self.editVulnItem(self.vulnList, self.vulnListModel))
        vulnRemoveButton = JButton("Remove", actionPerformed=lambda e: self.removeItem(self.vulnList, self.vulnListModel))

        # گروه ۳: Exclusion List
        exclLabel = JLabel("File Filters")
        exclLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        exclLabel.setForeground(Color(255, 102, 52))
        self.exclListModel = DefaultListModel()
        for item in JSExclusionList:
            self.exclListModel.addElement(item)
        self.exclList = JList(self.exclListModel)
        exclScrollPane = JScrollPane(self.exclList)
        exclAddButton = JButton("Add", actionPerformed=lambda e: self.addItem(self.exclListModel))
        exclAddMultipleButton = JButton("Add Multiple", actionPerformed=lambda e: self.addMultipleItems(self.exclListModel, "File Filters", False))
        exclEditButton = JButton("Edit", actionPerformed=lambda e: self.editItem(self.exclList, self.exclListModel))
        exclRemoveButton = JButton("Remove", actionPerformed=lambda e: self.removeItem(self.exclList, self.exclListModel))

        # گروه ۴: File Extensions
        extLabel = JLabel("File Extensions")
        extLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        extLabel.setForeground(Color(255, 102, 52))
        self.extListModel = DefaultListModel()
        for ext in FILE_EXTENSIONS:
            self.extListModel.addElement(ext)
        self.extList = JList(self.extListModel)
        extScrollPane = JScrollPane(self.extList)
        extAddButton = JButton("Add", actionPerformed=lambda e: self.addItem(self.extListModel))
        extAddMultipleButton = JButton("Add Multiple", actionPerformed=lambda e: self.addMultipleItems(self.extListModel, "File Extensions", False))
        extEditButton = JButton("Edit", actionPerformed=lambda e: self.editItem(self.extList, self.extListModel))
        extRemoveButton = JButton("Remove", actionPerformed=lambda e: self.removeItem(self.extList, self.extListModel))
        # توی initUI، بعد از تعریف بقیه چک‌باکس‌ها مثل logCheckboxes


        # گروه ۵: Log Severity
        logLabel = JLabel("Log Options")
        logLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        logLabel.setForeground(Color(255, 102, 52))
        self.logCheckboxes = {
            'Sensitive Data': JCheckBox("Sensitive Data", selected='Sensitive Data' in ENABLED_LOGS),
            'API Endpoints': JCheckBox("API Endpoints", selected='API Endpoints' in ENABLED_LOGS),
            'Comments': JCheckBox("Comments", selected='Comments' in ENABLED_LOGS),
            'General Links': JCheckBox("General Links", selected='General Links' in ENABLED_LOGS)
        }

        self.generalHttpCheckbox = JCheckBox("Enable General HTTP Scanning", selected=ENABLE_GENERAL_HTTP_SCANNING)

        # گروه ۶: Output Format
        outputLabel = JLabel("Output Format")
        outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        outputLabel.setForeground(Color(255, 102, 52))
        self.outputRadios = {
            'Plain Text': JRadioButton("Plain Text", selected=OUTPUT_FORMAT == 'Plain Text'),
            'JSON': JRadioButton("JSON", selected=OUTPUT_FORMAT == 'JSON'),
            'Detailed List': JRadioButton("Detailed List", selected=OUTPUT_FORMAT == 'Detailed List')
        }
        outputGroup = ButtonGroup()
        for radio in self.outputRadios.values():
            outputGroup.add(radio)




        # گروه ۷: Thread Pool Size
        threadPoolLabel = JLabel("Thread Pool Size")
        threadPoolLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        threadPoolLabel.setForeground(Color(255, 102, 52))
        self.threadPoolField = JTextField(str(THREAD_POOL_SIZE), 5)
        applyThreadPoolButton = JButton("Apply", actionPerformed=self.applyThreadPoolSize)




        # یه گروه جدید برای این تنظیم
        generalHttpLabel = JLabel("HTTP Scanning Options")
        generalHttpLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        generalHttpLabel.setForeground(Color(255, 102, 52))


        # پنل دکمه‌های عملیاتی
        actionPanel = JPanel()
        actionLayout = GroupLayout(actionPanel)
        actionPanel.setLayout(actionLayout)
        actionLayout.setAutoCreateGaps(True)
        actionLayout.setAutoCreateContainerGaps(True)
        saveButton = JButton("Save All Settings", actionPerformed=self.saveAllSettings)
        saveButton.setBackground(Color(0, 153, 0))  # سبز
        saveButton.setForeground(Color.WHITE)
        exportSettingsButton = JButton("Export Settings", actionPerformed=self.exportSettings)
        importSettingsButton = JButton("Import Settings", actionPerformed=self.importSettings)
        resetButton = JButton("Reset to Defaults", actionPerformed=self.resetToDefaults)
        resetButton.setBackground(Color(204, 0, 0))  # قرمز
        resetButton.setForeground(Color.WHITE)
        actionLayout.setHorizontalGroup(
            actionLayout.createSequentialGroup()
                .addComponent(saveButton)
                .addComponent(exportSettingsButton)
                .addComponent(importSettingsButton)
                .addComponent(resetButton)
        )
        actionLayout.setVerticalGroup(
            actionLayout.createParallelGroup()
                .addComponent(saveButton)
                .addComponent(exportSettingsButton)
                .addComponent(importSettingsButton)
                .addComponent(resetButton)
        )

        # چیدمان تب Settings
        settingsLayout.setHorizontalGroup(
            settingsLayout.createParallelGroup()
                # گروه ۱: API Patterns
                .addComponent(apiLabel)
                .addComponent(apiScrollPane)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(apiAddButton)
                    .addComponent(apiAddMultipleButton)
                    .addComponent(apiEditButton)
                    .addComponent(apiRemoveButton))
                .addComponent(separator)
                # گروه ۲: Vulnerability Patterns
                .addComponent(vulnLabel)
                .addComponent(vulnScrollPane)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(vulnAddButton)
                    .addComponent(vulnAddMultipleButton)
                    .addComponent(vulnEditButton)
                    .addComponent(vulnRemoveButton))
                .addComponent(separator)
                # گروه ۳: Exclusion List
                .addComponent(exclLabel)
                .addComponent(exclScrollPane)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(exclAddButton)
                    .addComponent(exclAddMultipleButton)
                    .addComponent(exclEditButton)
                    .addComponent(exclRemoveButton))
                .addComponent(separator)
                # گروه ۴: File Extensions
                .addComponent(extLabel)
                .addComponent(extScrollPane)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(extAddButton)
                    .addComponent(extAddMultipleButton)
                    .addComponent(extEditButton)
                    .addComponent(extRemoveButton))
                .addComponent(separator)
                # گروه ۵: Log Severity
                .addComponent(logLabel)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(self.logCheckboxes['Sensitive Data'])
                    .addComponent(self.logCheckboxes['API Endpoints'])
                    .addComponent(self.logCheckboxes['Comments'])
                    .addComponent(self.logCheckboxes['General Links']))
                .addComponent(separator)
                # گروه ۶: Output Format
                .addComponent(outputLabel)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(self.outputRadios['Plain Text'])
                    .addComponent(self.outputRadios['JSON'])
                    .addComponent(self.outputRadios['Detailed List']))
                .addComponent(separator)
                # گروه ۷: Thread Pool Size
                .addComponent(threadPoolLabel)
                .addGroup(settingsLayout.createSequentialGroup()
                    .addComponent(self.threadPoolField)
                    .addComponent(applyThreadPoolButton))
                .addComponent(separator)
                # پنل دکمه‌های عملیاتی
                .addComponent(actionPanel)

                .addComponent(separator)
                        .addComponent(generalHttpLabel)
                        .addComponent(self.generalHttpCheckbox)
        )
        settingsLayout.setVerticalGroup(
            settingsLayout.createSequentialGroup()
                # گروه ۱: API Patterns
                .addComponent(apiLabel)
                .addComponent(apiScrollPane)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(apiAddButton)
                    .addComponent(apiAddMultipleButton)
                    .addComponent(apiEditButton)
                    .addComponent(apiRemoveButton))
                .addComponent(separator)
                # گروه ۲: Vulnerability Patterns
                .addComponent(vulnLabel)
                .addComponent(vulnScrollPane)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(vulnAddButton)
                    .addComponent(vulnAddMultipleButton)
                    .addComponent(vulnEditButton)
                    .addComponent(vulnRemoveButton))
                .addComponent(separator)
                # گروه ۳: Exclusion List
                .addComponent(exclLabel)
                .addComponent(exclScrollPane)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(exclAddButton)
                    .addComponent(exclAddMultipleButton)
                    .addComponent(exclEditButton)
                    .addComponent(exclRemoveButton))
                .addComponent(separator)
                # گروه ۴: File Extensions
                .addComponent(extLabel)
                .addComponent(extScrollPane)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(extAddButton)
                    .addComponent(extAddMultipleButton)
                    .addComponent(extEditButton)
                    .addComponent(extRemoveButton))
                .addComponent(separator)
                # گروه ۵: Log Severity
                .addComponent(logLabel)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(self.logCheckboxes['Sensitive Data'])
                    .addComponent(self.logCheckboxes['API Endpoints'])
                    .addComponent(self.logCheckboxes['Comments'])
                    .addComponent(self.logCheckboxes['General Links']))
                .addComponent(separator)
                # گروه ۶: Output Format
                .addComponent(outputLabel)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(self.outputRadios['Plain Text'])
                    .addComponent(self.outputRadios['JSON'])
                    .addComponent(self.outputRadios['Detailed List']))
                .addComponent(separator)
                # گروه ۷: Thread Pool Size
                .addComponent(threadPoolLabel)
                .addGroup(settingsLayout.createParallelGroup()
                    .addComponent(self.threadPoolField)
                    .addComponent(applyThreadPoolButton))
                .addComponent(separator)
                # پنل دکمه‌های عملیاتی
                .addComponent(actionPanel)

                .addComponent(separator)
                        .addComponent(generalHttpLabel)
                        .addComponent(self.generalHttpCheckbox)

        )

        # کل تب Settings رو توی JScrollPane می‌ذاریم
        settingsScrollPane = JScrollPane(settingsPanel)
        settingsScrollPane.getVerticalScrollBar().setUnitIncrement(16)  # سرعت اسکرول با هر حرکت غلطک
        settingsScrollPane.getVerticalScrollBar().setBlockIncrement(50)  # سرعت اسکرول با کلیک روی اسکرول‌بار

        # اضافه کردن تب‌ها به UI اصلی
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(self.tabbedPane)
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(self.tabbedPane)
        )
        self.tabbedPane.addTab("Settings", settingsScrollPane)

    def addItem(self, listModel):
        item = JOptionPane.showInputDialog(self.tab, "Enter new item:")
        if item:
            listModel.addElement(item)
            self.saveAllSettings(None)  # ذخیره خودکار بعد از اضافه کردن

    def addMultipleItems(self, listModel, title, validate_regex=False):
        """اضافه کردن چندین آیتم به صورت همزمان"""
        dialog = JDialog()
        dialog.setTitle("Add Multiple Items - {}".format(title))
        dialog.setModal(True)
        dialog.setSize(Dimension(400, 300))
        dialog.setLayout(BorderLayout())

        instructionLabel = JLabel("Enter each item on a new line:")
        instructionLabel.setFont(Font("Tahoma", Font.PLAIN, 12))
        textArea = JTextArea()
        textArea.setFont(Font("Consolas", Font.PLAIN, 12))
        scrollPane = JScrollPane(textArea)
        confirmButton = JButton("Confirm", actionPerformed=lambda e: self.confirmMultipleItems(dialog, listModel, textArea, validate_regex))
        cancelButton = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())

        buttonPanel = JPanel()
        buttonLayout = GroupLayout(buttonPanel)
        buttonPanel.setLayout(buttonLayout)
        buttonLayout.setAutoCreateGaps(True)
        buttonLayout.setAutoCreateContainerGaps(True)
        buttonLayout.setHorizontalGroup(
            buttonLayout.createSequentialGroup()
                .addComponent(confirmButton)
                .addComponent(cancelButton)
        )
        buttonLayout.setVerticalGroup(
            buttonLayout.createParallelGroup()
                .addComponent(confirmButton)
                .addComponent(cancelButton)
        )

        dialog.add(instructionLabel, BorderLayout.NORTH)
        dialog.add(scrollPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(self.tab)
        dialog.setVisible(True)

    def confirmMultipleItems(self, dialog, listModel, textArea, validate_regex):
        """تأیید و اضافه کردن آیتم‌ها به لیست"""
        items = textArea.getText().splitlines()
        valid_items = []
        invalid_items = []
        for item in items:
            item = item.strip()
            if item:
                if validate_regex:
                    try:
                        re.compile(item)  # اعتبارسنجی رجکس
                        valid_items.append(item)
                    except re.error:
                        invalid_items.append(item)
                else:
                    valid_items.append(item)
        if invalid_items:
            error_msg = "The following items are invalid regex patterns and will be skipped:\n" + "\n".join(invalid_items)
            JOptionPane.showMessageDialog(self.tab, error_msg, "Invalid Patterns", JOptionPane.WARNING_MESSAGE)
        for item in valid_items:
            listModel.addElement(item)
        self.saveAllSettings(None)  # ذخیره خودکار
        dialog.dispose()

    def addVulnItem(self, listModel):
        vulnType = JOptionPane.showInputDialog(self.tab, "Enter vulnerability type (e.g., XSS, SQLi):")
        if vulnType:
            pattern = JOptionPane.showInputDialog(self.tab, "Enter regex pattern for {}:".format(vulnType))
            if pattern:
                listModel.addElement("{}: {}".format(vulnType, pattern))
                self.saveAllSettings(None)  # ذخیره خودکار بعد از اضافه کردن

    def addMultipleVulnItems(self, listModel, title):
        """اضافه کردن چندین آیتم آسیب‌پذیری به صورت همزمان"""
        dialog = JDialog()
        dialog.setTitle("Add Multiple Items - {}".format(title))
        dialog.setModal(True)
        dialog.setSize(Dimension(400, 300))
        dialog.setLayout(BorderLayout())

        instructionLabel = JLabel("Enter each item as 'type: pattern' on a new line (e.g., XSS: alert\\():")
        instructionLabel.setFont(Font("Tahoma", Font.PLAIN, 12))
        textArea = JTextArea()
        textArea.setFont(Font("Consolas", Font.PLAIN, 12))
        scrollPane = JScrollPane(textArea)
        confirmButton = JButton("Confirm", actionPerformed=lambda e: self.confirmMultipleVulnItems(dialog, listModel, textArea))
        cancelButton = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())

        buttonPanel = JPanel()
        buttonLayout = GroupLayout(buttonPanel)
        buttonPanel.setLayout(buttonLayout)
        buttonLayout.setAutoCreateGaps(True)
        buttonLayout.setAutoCreateContainerGaps(True)
        buttonLayout.setHorizontalGroup(
            buttonLayout.createSequentialGroup()
                .addComponent(confirmButton)
                .addComponent(cancelButton)
        )
        buttonLayout.setVerticalGroup(
            buttonLayout.createParallelGroup()
                .addComponent(confirmButton)
                .addComponent(cancelButton)
        )

        dialog.add(instructionLabel, BorderLayout.NORTH)
        dialog.add(scrollPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(self.tab)
        dialog.setVisible(True)

    def confirmMultipleVulnItems(self, dialog, listModel, textArea):
        """تأیید و اضافه کردن آیتم‌های آسیب‌پذیری به لیست"""
        items = textArea.getText().splitlines()
        valid_items = []
        invalid_items = []
        for item in items:
            item = item.strip()
            if item:
                try:
                    vuln_type, pattern = item.split(": ", 1)
                    re.compile(pattern)  # اعتبارسنجی رجکس
                    valid_items.append(item)
                except (ValueError, re.error):
                    invalid_items.append(item)
        if invalid_items:
            error_msg = "The following items are invalid and will be skipped:\n" + "\n".join(invalid_items)
            JOptionPane.showMessageDialog(self.tab, error_msg, "Invalid Patterns", JOptionPane.WARNING_MESSAGE)
        for item in valid_items:
            listModel.addElement(item)
        self.saveAllSettings(None)  # ذخیره خودکار
        dialog.dispose()

    def editItem(self, jList, listModel):
        selectedIndex = jList.getSelectedIndex()
        if selectedIndex != -1:
            currentItem = listModel.getElementAt(selectedIndex)
            newItem = JOptionPane.showInputDialog(self.tab, "Edit item:", currentItem)
            if newItem:
                listModel.setElementAt(newItem, selectedIndex)
                self.saveAllSettings(None)  # ذخیره خودکار بعد از ویرایش

    def editVulnItem(self, jList, listModel):
        selectedIndex = jList.getSelectedIndex()
        if selectedIndex != -1:
            currentItem = listModel.getElementAt(selectedIndex)
            vulnType, pattern = currentItem.split(": ", 1)
            newVulnType = JOptionPane.showInputDialog(self.tab, "Edit vulnerability type:", vulnType)
            if newVulnType:
                newPattern = JOptionPane.showInputDialog(self.tab, "Edit regex pattern:", pattern)
                if newPattern:
                    listModel.setElementAt("{}: {}".format(newVulnType, newPattern), selectedIndex)
                    self.saveAllSettings(None)  # ذخیره خودکار بعد از ویرایش

    def removeItem(self, jList, listModel):
        selectedIndex = jList.getSelectedIndex()
        if selectedIndex != -1:
            listModel.remove(selectedIndex)
            self.saveAllSettings(None)  # ذخیره خودکار بعد از حذف

    def exportSettings(self, event):
        global JSExclusionList, API_PATTERN_STRINGS, VULN_PATTERNS, ENABLED_LOGS, OUTPUT_FORMAT, FILE_EXTENSIONS, THREAD_POOL_SIZE
        settings["ENABLE_GENERAL_HTTP_SCANNING"] = ENABLE_GENERAL_HTTP_SCANNING
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooser.getSelectedFile().getAbsolutePath()
            settings = {
                "JSExclusionList": JSExclusionList,
                "API_PATTERN_STRINGS": API_PATTERN_STRINGS,
                "VULN_PATTERNS": VULN_PATTERNS,
                "ENABLED_LOGS": ENABLED_LOGS,
                "OUTPUT_FORMAT": OUTPUT_FORMAT,
                "FILE_EXTENSIONS": FILE_EXTENSIONS,
                "THREAD_POOL_SIZE": THREAD_POOL_SIZE
            }
            try:
                with open(filename, "w") as file:
                    file.write(json.dumps(settings, indent=2))
                self.log("Settings exported to {}".format(filename))
            except Exception as e:
                self.stderr.println("Error exporting settings: {}".format(str(e)))

    def importSettings(self, event):
        global JSExclusionList, API_PATTERN_STRINGS, VULN_PATTERNS, ENABLED_LOGS, OUTPUT_FORMAT, FILE_EXTENSIONS, API_PATTERNS, THREAD_POOL_SIZE
        ENABLE_GENERAL_HTTP_SCANNING = settings.get("ENABLE_GENERAL_HTTP_SCANNING", ENABLE_GENERAL_HTTP_SCANNING)
        self.generalHttpCheckbox.setSelected(ENABLE_GENERAL_HTTP_SCANNING)
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(filename, "r") as file:
                    settings = json.load(file)
                JSExclusionList = settings.get("JSExclusionList", JSExclusionList)
                API_PATTERN_STRINGS = settings.get("API_PATTERN_STRINGS", API_PATTERN_STRINGS)
                API_PATTERNS = [re.compile(pattern) for pattern in API_PATTERN_STRINGS]
                VULN_PATTERNS = settings.get("VULN_PATTERNS", VULN_PATTERNS)
                ENABLED_LOGS = settings.get("ENABLED_LOGS", ENABLED_LOGS)
                OUTPUT_FORMAT = settings.get("OUTPUT_FORMAT", OUTPUT_FORMAT)
                FILE_EXTENSIONS = settings.get("FILE_EXTENSIONS", FILE_EXTENSIONS)
                THREAD_POOL_SIZE = settings.get("THREAD_POOL_SIZE", THREAD_POOL_SIZE)
                # بازسازی Thread Pool با تعداد جدید
                self.threadPool.shutdown()
                self.threadPool = Executors.newFixedThreadPool(THREAD_POOL_SIZE)
                # آپدیت UI
                self.exclListModel.clear()
                for item in JSExclusionList:
                    self.exclListModel.addElement(item)
                self.apiListModel.clear()
                for pattern in API_PATTERN_STRINGS:
                    self.apiListModel.addElement(pattern)
                self.vulnListModel.clear()
                for vuln_type, patterns in VULN_PATTERNS.items():
                    for pattern in patterns:
                        self.vulnListModel.addElement("{}: {}".format(vuln_type, pattern))
                for key, checkbox in self.logCheckboxes.items():
                    checkbox.setSelected(key in ENABLED_LOGS)
                for fmt, radio in self.outputRadios.items():
                    radio.setSelected(fmt == OUTPUT_FORMAT)
                self.extListModel.clear()
                for ext in FILE_EXTENSIONS:
                    self.extListModel.addElement(ext)
                self.threadPoolField.setText(str(THREAD_POOL_SIZE))
                self.log("Settings imported from {}".format(filename))
            except Exception as e:
                self.stderr.println("Error importing settings: {}".format(str(e)))

    def applyThreadPoolSize(self, event):
        global THREAD_POOL_SIZE
        try:
            new_size = int(self.threadPoolField.getText().strip())
            if new_size < 1:
                raise ValueError("Thread pool size must be at least 1")
            THREAD_POOL_SIZE = new_size
            self.threadPool.shutdown()
            self.threadPool = Executors.newFixedThreadPool(THREAD_POOL_SIZE)
            self.log("Thread pool size updated to {}".format(THREAD_POOL_SIZE))
        except ValueError as e:
            self.stderr.println("Invalid thread pool size: {}".format(str(e)))
            self.log("Invalid thread pool size: {}".format(str(e)))

    def saveAllSettings(self, event):
        global JSExclusionList, API_PATTERN_STRINGS, VULN_PATTERNS, ENABLED_LOGS, OUTPUT_FORMAT, FILE_EXTENSIONS, API_PATTERNS
        global ENABLE_GENERAL_HTTP_SCANNING
        ENABLE_GENERAL_HTTP_SCANNING = self.generalHttpCheckbox.isSelected()
        try:
            JSExclusionList = [self.exclListModel.getElementAt(i) for i in range(self.exclListModel.getSize())]
            API_PATTERN_STRINGS = [self.apiListModel.getElementAt(i) for i in range(self.apiListModel.getSize())]
            API_PATTERNS = [re.compile(pattern) for pattern in API_PATTERN_STRINGS]
            ENABLED_LOGS = [key for key, checkbox in self.logCheckboxes.items() if checkbox.isSelected()]
            # برای Vulnerability Patterns
            VULN_PATTERNS = {}
            for i in range(self.vulnListModel.getSize()):
                item = self.vulnListModel.getElementAt(i)
                vuln_type, pattern = item.split(": ", 1)
                if vuln_type not in VULN_PATTERNS:
                    VULN_PATTERNS[vuln_type] = []
                VULN_PATTERNS[vuln_type].append(pattern)
            for fmt, radio in self.outputRadios.items():
                if radio.isSelected():
                    OUTPUT_FORMAT = fmt
                    break
            FILE_EXTENSIONS = [self.extListModel.getElementAt(i) for i in range(self.extListModel.getSize())]
            self.log("All settings saved successfully!")
        except Exception as e:
            self.stderr.println("Error saving settings: {}".format(str(e)))
            self.log("Error saving settings: {}".format(str(e)))

    def resetToDefaults(self, event):
        """ریست کردن همه تنظیمات به مقادیر پیش‌فرض"""
        global JSExclusionList, API_PATTERN_STRINGS, VULN_PATTERNS, ENABLED_LOGS, OUTPUT_FORMAT, FILE_EXTENSIONS, THREAD_POOL_SIZE, API_PATTERNS, SENSITIVE_PATTERNS
        ENABLE_GENERAL_HTTP_SCANNING = False
        self.generalHttpCheckbox.setSelected(ENABLE_GENERAL_HTTP_SCANNING)
        # مقادیر پیش‌فرض (دقیقاً همون مقادیری که توی ابتدای کد تعریف شدن)
        JSExclusionList = ['jquery', 'google-analytics', 'gpt.js']
        API_PATTERN_STRINGS = [
            r'/api/[a-zA-Z0-9_\-/]+',
            r'/v\d+/api/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+/api/v\d+/[a-zA-Z0-9_\-/]+',
            r'/api-v\d+/[a-zA-Z0-9_\-/]+',
            r'(?:/rest|/rest-api)/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+-rest/[a-zA-Z0-9_\-/]+',
            r'/v\d+/[a-zA-Z0-9_\-/]+',
            r'/version\d+/[a-zA-Z0-9_\-/]+',
            r'/legacy-v\d+/[a-zA-Z0-9_\-/]+',
            r'/v[a-zA-Z0-9]+/.*',
            r'/service/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+-service/[a-zA-Z0-9_\-/]+',
            r'/service-api/[a-zA-Z0-9_\-/]+',
            r'/graphql(?:\?.*)?',
            r'/[a-zA-Z0-9_\-]+-graphql(?:\?.*)?',
            r'(?:/ws|wss://)[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+(?:-ws|-wss)/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+/socket/[a-zA-Z0-9_\-/]+',
            r'(?:/rpc|/json-rpc)/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+(?:-rpc|-json-rpc)/[a-zA-Z0-9_\-/]+',
            r'/soap/[a-zA-Z0-9_\-/]+',
            r'/[a-zA-Z0-9_\-]+-soap/[a-zA-Z0-9_\-/]+',
            r'/admin(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/administrator(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/console(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/panel(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/backend(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/system(?:/api)?/[a-zA-Z0-9_\-/]+',
            r'/auth/[a-zA-Z0-9_\-/]+',
            r'/authentication/[a-zA-Z0-9_\-/]+',
            r'/login(?:/[a-zA-Z0-9_\-]+)?',
            r'/logout(?:/[a-zA-Z0-9_\-]+)?',
            r'/signup(?:/[a-zA-Z0-9_\-]+)?',
            r'/register(?:/[a-zA-Z0-9_\-]+)?',
            r'/oauth(?:/[a-zA-Z0-9_\-]+)?',
            r'/sso(?:/[a-zA-Z0-9_\-]+)?',
            r'/token(?:/[a-zA-Z0-9_\-]+)?',
            r'/user(?:s)?/[a-zA-Z0-9_\-/]+',
            r'/profile(?:/[a-zA-Z0-9_\-]+)?',
            r'/account(?:/[a-zA-Z0-9_\-]+)?',
            r'/customer(?:s)?/[a-zA-Z0-9_\-/]+',
            r'/member(?:s)?/[a-zA-Z0-9_\-/]+',
            r'/client(?:s)?/[a-zA-Z0-9_\-/]+',
            r'/swagger(?:-ui)?(?:/[a-zA-Z0-9_\-]+)?',
            r'/api-docs(?:/[a-zA-Z0-9_\-]+)?',
            r'/openapi(?:/[a-zA-Z0-9_\-]+)?',
            r'/redoc(?:/[a-zA-Z0-9_\-]+)?',
            r'/(?:api-|)documentation(?:/[a-zA-Z0-9_\-]+)?',
            r'/(?:api-|)reference(?:/[a-zA-Z0-9_\-]+)?',
            r'/[a-zA-Z0-9_]+-api',
            r'/endpoints',
            r'/gateway',
            r'/entrypoint',
            r'/[a-zA-Z0-9_]+/v\d+',
            r'/[a-zA-Z0-9_]+\.asmx(?:/[a-zA-Z0-9_\-]+)?',
            r'/[a-zA-Z0-9_]+\.cfc(?:/[a-zA-Z0-9_\-]+)?',
            r'/[a-zA-Z0-9_]+\.jhtml(?:/[a-zA-Z0-9_\-]+)?',
            r'/[a-zA-Z0-9_]+\.action(?:/[a-zA-Z0-9_\-]+)?',
            r'/internal(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/private(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/protected(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/restricted(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/hidden(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/external(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/public(?:-api)?/[a-zA-Z0-9_\-/]+',
            r'/mobile(?:/v\d+)?/[a-zA-Z0-9_\-/]+'
        ]
        API_PATTERNS = [re.compile(pattern) for pattern in API_PATTERN_STRINGS]
        VULN_PATTERNS = {
            'XSS': [r'<script>', r'alert\(', r'onerror='],
            'SQLi': [r'\bUNION\b.*\bSELECT\b', r'\bDROP\b.*\bTABLE\b', r'\bOR\b\s*\d+\s*=\s*\d+']
        }
        SENSITIVE_PATTERNS = {
            'Stripe API Keys': r"(?:const|var|let)\s+S\d+\s*=\s*'(pk_live_|sk_live_).+';",
            'Variable Definition with Long Value': r'(var|let|const)\s+(\w+\$?\d*)\s*=\s*"([A-Za-z0-9_-]{20,})"',
            'Stripe Key': r'(sk_live|pk_live)_[0-9a-zA-Z]{24}'
        }
        ENABLED_LOGS = ['Sensitive Data', 'API Endpoints', 'Comments', 'General Links']
        OUTPUT_FORMAT = 'Plain Text'
        FILE_EXTENSIONS = ['js', 'json']
        THREAD_POOL_SIZE = 4
        
        # بازسازی Thread Pool با تعداد پیش‌فرض
        self.threadPool.shutdown()
        self.threadPool = Executors.newFixedThreadPool(THREAD_POOL_SIZE)
        
        # آپدیت UI
        self.exclListModel.clear()
        for item in JSExclusionList:
            self.exclListModel.addElement(item)
        self.apiListModel.clear()
        for pattern in API_PATTERN_STRINGS:
            self.apiListModel.addElement(pattern)
        self.vulnListModel.clear()
        for vuln_type, patterns in VULN_PATTERNS.items():
            for pattern in patterns:
                self.vulnListModel.addElement("{}: {}".format(vuln_type, pattern))
        for key, checkbox in self.logCheckboxes.items():
            checkbox.setSelected(key in ENABLED_LOGS)
        for fmt, radio in self.outputRadios.items():
            radio.setSelected(fmt == OUTPUT_FORMAT)
        self.extListModel.clear()
        for ext in FILE_EXTENSIONS:
            self.extListModel.addElement(ext)
        self.threadPoolField.setText(str(THREAD_POOL_SIZE))
        
        self.log("Settings reset to defaults.")

    def exportText(self, textArea):
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(filename, "w") as file:
                    file.write(textArea.getText())
                self.log("Data exported to {}".format(filename))
            except Exception as e:
                self.stderr.println("Error exporting data: {}".format(str(e)))

    def getTabCaption(self):
        return "JS_Extractor"

    def getUiComponent(self):
        return self.tab

    def logComments(self, comments, url):
        if 'Comments' not in ENABLED_LOGS:
            return
        with self.logLock:
            if comments:
                if OUTPUT_FORMAT == 'JSON':
                    shortened_comments = [comment[:100] + " [...]" if len(comment) > 100 else comment for comment in comments]
                    output = json.dumps({"url": str(url), "comments": shortened_comments}) + "\n"
                elif OUTPUT_FORMAT == 'Detailed List':
                    output = "[+] Comments Found in: [{}]\n".format(url)
                    for comment in comments:
                        if len(comment) > 100:
                            shortened_comment = comment[:100] + " [...]"
                            output += "\tComment: {}\n".format(shortened_comment)
                        else:
                            output += "\tComment: {}\n".format(comment)
                    output += "\n"
                else:
                    output = "[+] Comments Found in: [{}]\n".format(url)
                    for comment in comments:
                        if len(comment) > 100:
                            shortened_comment = comment[:100] + " [...]"
                            output += "\t{}\n".format(shortened_comment)
                        else:
                            output += "\t{}\n".format(comment)
                    output += "\n"
                self.commentsTxtArea.append(output)

    def logAPIEndpoints(self, endpoints, url):
        if 'API Endpoints' not in ENABLED_LOGS:
            return
        with self.logLock:
            if endpoints:
                if OUTPUT_FORMAT == 'JSON':
                    output = json.dumps({"url": str(url), "endpoints": [e['endpoint'] for e in endpoints]}) + "\n"
                elif OUTPUT_FORMAT == 'Detailed List':
                    output = "[+] API Path Found in: {}\n".format(url)
                    for endpoint in endpoints:
                        output += "\tEndpoint: {}\n".format(endpoint['endpoint'])
                    output += "\n"
                else:
                    output = "[+] API Path Found in: {}\n".format(url)
                    for endpoint in endpoints:
                        output += "\t{}\n".format(endpoint['endpoint'])
                    output += "\n"
                self.apiEndpointsTxtArea.append(output)

    def logSensitiveData(self, data, url):
        if 'Sensitive Data' not in ENABLED_LOGS:
            return
        with self.logLock:
            if data:
                if OUTPUT_FORMAT == 'JSON':
                    output = json.dumps({"url": str(url), "sensitive_data": [{"type": d["type"], "value": d["value"]} for d in data]}) + "\n"
                elif OUTPUT_FORMAT == 'Detailed List':
                    output = "[+] Sensitive Data Found in: {}\n".format(url)
                    for item in data:
                        output += "\t{}: {}\n".format(item["type"], item["value"])
                    output += "\n"
                else:
                    output = "[+] Sensitive Data Found in: {}\n".format(url)
                    for item in data:
                        output += "\t- {}: {}\n".format(item["type"], item["value"])
                    output += "\n"
                self.sensitiveDataTxtArea.append(output)

    def logGeneralOutput(self, message):
        if 'General Links' not in ENABLED_LOGS:
            return
        with self.logLock:
            if OUTPUT_FORMAT == 'JSON':
                self.generalOutputTxtArea.append(json.dumps({"message": message}) + "\n")
            else:
                self.generalOutputTxtArea.append(message + "\n")

    def log(self, message):
        with self.logLock:
            if OUTPUT_FORMAT == 'JSON':
                self.generalOutputTxtArea.append(json.dumps({"message": message}) + "\n")
            else:
                self.generalOutputTxtArea.append(message + "\n")

    def detect_content_type(self, ihrr):
        try:
            response = ihrr.getResponse()
            if not response:
                return None
            # چک کردن هدر Content-Type
            headers = self.helpers.analyzeResponse(response).getHeaders()
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip().lower()
                    if "javascript" in content_type or "ecmascript" in content_type:
                        return "script"
                    elif "json" in content_type:
                        return "json"
                    elif "html" in content_type:
                        return "text/html"
            # اگه از هدرها چیزی نگرفتیم، محتوای بدنه رو چک می‌کنیم
            decoded_resp = self.helpers.bytesToString(response)
            js_pattern = re.compile(r'(function|var|let|const|\{.*\}|;)', re.IGNORECASE)
            if js_pattern.search(decoded_resp):
                return "script"
            decoded_resp = decoded_resp.strip()
            if decoded_resp.startswith('{') and decoded_resp.endswith('}'):
                try:
                    json.loads(decoded_resp)
                    return "json"
                except:
                    pass
            html_pattern = re.compile(r'<script\s+src=["\'](.*?)["\']>|<link\s+href=["\'](.*?)["\']>', re.IGNORECASE)
            if html_pattern.search(decoded_resp):
                return "text/html"
            return None
        except Exception as e:
            self.stderr.println("Error detecting content type: {}".format(str(e)))
            return None

    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            url_str = str(urlReq).lower()
            content_type = self.detect_content_type(ihrr)
            # شرط جدید برای اسکن
            if ENABLE_GENERAL_HTTP_SCANNING:
                self.log("[+] Scanning HTTP Request: {} (Detected as {})".format(urlReq, content_type or "general"))
            elif (any(ext in url_str for ext in FILE_EXTENSIONS) or content_type in ["script", "json", "text/html"]) \
                and not any(ex in url_str for ex in JSExclusionList):
                self.log("[+] Valid URL: {} (Detected as {})".format(urlReq, content_type or "extension-based"))
            else:
                return None  # اگر هیچ‌کدوم از شرط‌ها صدق نکنه، اسکن نمی‌کنیم

            # لیست وظایف برای اجرا در تردها
            tasks = [
                (self.extractLinks, [ihrr], self.logGeneralOutput),
                (self.extractComments, [ihrr], self.logComments),
                (self.extractSensitiveData, [ihrr], self.logSensitiveData),
                (self.findInsecureConnections, [ihrr], self.logGeneralOutput),
                (self.findAPIEndpoints, [ihrr], self.logAPIEndpoints),
                (self.findDebugStatements, [ihrr], self.logGeneralOutput),
                (self.findBase64Strings, [ihrr], self.logGeneralOutput),
                (self.extractIPAddresses, [ihrr], self.logGeneralOutput),
                (self.decodeURLEncodedStrings, [ihrr], self.logGeneralOutput),
                (self.detectVulnerabilities, [ihrr], self.logGeneralOutput)
            ]

            if ".json" in url_str or content_type == "json":
                self.log("[+] Valid JSON URL: {}".format(urlReq))
                tasks.append((self.extractJSONData, [ihrr], self.logGeneralOutput))

            for task_func, args, log_func in tasks:
                self.threadPool.submit(lambda f=task_func, a=args, l=log_func: self.run_task(f, a, l))

        except Exception as e:
            self.stderr.println("Error during passive scan: {}".format(str(e)))
        return None

    def run_task(self, task_func, args, log_func):
        try:
            results = task_func(*args)
            if results and log_func:
                url = args[0].getUrl() if task_func in [self.extractComments, self.findAPIEndpoints, self.extractSensitiveData] else None
                if url:  # برای توابعی که URL لازم دارن
                    log_func(results, url)
                elif isinstance(results, list):  # برای لیست نتایج
                    for result in results:
                        if isinstance(result, dict):  # اگر دیکشنری باشه
                            if 'link' in result:
                                log_func("\t[Link] {}".format(result['link']))
                            elif 'ip' in result:
                                log_func("\t[IP Address] {}".format(result['ip']))
                            elif 'decoded' in result:
                                log_func("\t[Decoded] {}".format(result['decoded']))
                            elif 'statement' in result:
                                log_func("\t[Debug Statement] {}".format(result['statement']))
                            elif 'data' in result:
                                log_func("\t[JSON Data] {}".format(result['data']))
                        else:  # برای نتایج ساده (مثل detectVulnerabilities)
                            log_func("\t[Result] {}".format(result))
        except Exception as e:
            self.stderr.println("Error in task {}: {}".format(task_func.__name__, str(e)))

    def extractLinks(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:  # فقط چک می‌کنیم که پاسخ خالی نباشه
                decoded_resp = self.helpers.bytesToString(response)
                regex = re.compile(r"""
                    (?:"|'|`)\s*
                    (
                        (?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^\s"'`>]*  # URLهای کامل
                        |
                        (?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^\s"'`>()]+  # مسیرهای نسبی
                        |
                        [a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]+\.(?:[a-zA-Z]{1,6}|action)(?:[\?|/][^\s"'`>]*|)  # مسیرها با پسوند
                        |
                        [a-zA-Z0-9_\-.]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|css|svg|png|gif|jpg|jpeg|woff|ttf|eot|ico|map|md|yaml|yml)(?:\?[^\s"'`>]*|)  # فایل‌ها با پسوند
                        |
                        (?:mailto:|tel:|file:|ftp:|sftp:|ws:|wss:|ldap:|smb:|git:|ssh:|whoop:)[^\s"'`>]*  # طرح‌های URI + whoop:
                        |
                        \/api\/[a-zA-Z0-9_\-/]+(?:\?[^\s"'`>]*|)  # مسیرهای API
                        |
                        [a-zA-Z0-9_\-/]+\.(?:com|org|net|edu|gov|io|co|me|info|biz|app|dev|tech|online|site|xyz|club)(?:/[^\s"'`>]*|)  # TLDها
                        |
                        (?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/[^\s"'`>]*|)  # localhost
                        |
                        [a-zA-Z0-9_-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?:/[^\s"'`>]*|)  # دامنه‌های خام
                    )
                    \s*(?:"|'|`)
                    """, re.VERBOSE | re.IGNORECASE)

                links = set()
                for match in regex.finditer(decoded_resp):
                    link = match.group(1).strip()
                    if link and not any(ex in link for ex in JSExclusionList):
                        links.add(link)
                base64_regex = re.compile(r'[A-Za-z0-9+/=]{40,}')
                for match in base64_regex.finditer(decoded_resp):
                    try:
                        decoded = base64.b64decode(match.group(0)).decode('utf-8')
                        links.add(decoded)
                    except Exception:
                        pass
                return [{"link": link} for link in links]
        except Exception as e:
            self.stderr.println("Error extracting links: {}".format(str(e)))
        return []

    def extractSensitiveData(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                sensitive_data = []
                for name, pattern in SENSITIVE_PATTERNS.items():
                    regex = re.compile(pattern, re.IGNORECASE | re.VERBOSE)
                    matches = regex.finditer(decoded_resp)
                    for match in matches:
                        value = match.group(0).strip()
                        sensitive_data.append({"type": name, "value": value})
                url = ihrr.getUrl()
                self.logSensitiveData(sensitive_data, url)
                return sensitive_data
        except Exception as e:
            self.stderr.println("Error extracting sensitive data: {}".format(str(e)))
            return []

    def findAPIEndpoints(self, ihrr):
        try:
            links = self.extractLinks(ihrr)
            api_endpoints = []
            for link in links:
                for pattern in API_PATTERNS:
                    if re.search(pattern, link['link']):
                        api_endpoints.append({"endpoint": link['link']})
                        break
            url = ihrr.getUrl()
            self.logAPIEndpoints(api_endpoints, url)
            return api_endpoints
        except Exception as e:
            self.stderr.println("Error finding API endpoints: {}".format(str(e)))
        return []

    def extractJSONData(self, ihrr):
        try:
            response = ihrr.getResponse()
            decoded_resp = self.helpers.bytesToString(response)
            if decoded_resp.strip().startswith('{') and decoded_resp.strip().endswith('}'):
                json_data = json.loads(decoded_resp)
                sensitive_data = set()
                def extract_keys(data, parent_key=""):
                    if isinstance(data, dict):
                        for key, value in data.items():
                            full_key = "{}.{}".format(parent_key, key) if parent_key else key
                            if isinstance(value, (dict, list)):
                                extract_keys(value, full_key)
                            elif isinstance(value, str) and ('key' in full_key.lower() or 'url' in full_key.lower() or 'token' in full_key.lower() or 'password' in full_key.lower() or 'secret' in full_key.lower() or 'api_key' in full_key.lower() or 'id' in full_key.lower()):
                                sensitive_data.add("{}: {}".format(full_key, value))
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            extract_keys(item, "{}[{}]".format(parent_key, i))
                extract_keys(json_data)
                return [{"data": data} for data in sensitive_data]
        except Exception as e:
            self.stderr.println("Error extracting JSON data: {}".format(str(e)))
        return []

    def extractComments(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                comment_pattern = re.compile(r'(/\*.*?\*/|//.*?$)', re.MULTILINE | re.DOTALL)
                comments = comment_pattern.findall(decoded_resp)
                cleaned_comments = [comment.strip() for comment in comments]
                url = ihrr.getUrl()
                self.logComments(cleaned_comments, url)
                return cleaned_comments
        except Exception as e:
            self.stderr.println("Error extracting comments: {}".format(str(e)))
        return []

    def findInsecureConnections(self, ihrr):
        try:
            links = self.extractLinks(ihrr)
            insecure_links = [link for link in links if link['link'].startswith('http://')]
            return [{"link": link['link']} for link in insecure_links]
        except Exception as e:
            self.stderr.println("Error finding insecure connections: {}".format(str(e)))
        return []

    def extractIPAddresses(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                ip_regex = re.compile(r"(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4})(?![\w.-])", re.VERBOSE)
                matches = ip_regex.findall(decoded_resp)
                ip_addresses = set(matches)
                valid_ips = []
                for ip in ip_addresses:
                    if "." in ip:
                        octets = ip.split(".")
                        if len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets):
                            valid_ips.append(ip)
                    else:
                        valid_ips.append(ip)
                return [{"ip": ip} for ip in valid_ips]
        except Exception as e:
            self.stderr.println("Error extracting IP addresses: {}".format(str(e)))
        return []

    def decodeURLEncodedStrings(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                url_encoded_regex = re.compile(r'(%[0-9A-Fa-f]{2})+')
                matches = url_encoded_regex.finditer(decoded_resp)
                decoded_strings = set()
                for match in matches:
                    encoded_string = match.group(0)
                    try:
                        decoded = self.helpers.urlDecode(encoded_string)
                        decoded_strings.add(decoded)
                    except Exception:
                        pass
                return [{"decoded": string} for string in decoded_strings]
        except Exception as e:
            self.stderr.println("Error during URL-encoded decoding: {}".format(str(e)))
        return []

    def findDebugStatements(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                debug_regex = re.compile(r'(console\.log|debugger|alert)\s*\(')
                matches = debug_regex.findall(decoded_resp)
                return [{"statement": match} for match in matches]
        except Exception as e:
            self.stderr.println("Error finding debug statements: {}".format(str(e)))
        return []

    def findBase64Strings(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                base64_regex = re.compile(r'[A-Za-z0-9+/=]{40,}')
                matches = base64_regex.finditer(decoded_resp)
                decoded_strings = []
                for match in matches:
                    try:
                        decoded = base64.b64decode(match.group(0)).decode('utf-8')
                        decoded_strings.append(decoded)
                    except Exception:
                        pass
                return [{"decoded": string} for string in decoded_strings]
        except Exception as e:
            self.stderr.println("Error finding Base64 strings: {}".format(str(e)))
        return []

    def detectVulnerabilities(self, ihrr):
        try:
            response = ihrr.getResponse()
            if response:
                decoded_resp = self.helpers.bytesToString(response)
                vulnerabilities = []
                for vuln_type, regex_list in VULN_PATTERNS.items():
                    for pattern in regex_list:
                        for match in re.finditer(pattern, decoded_resp, re.IGNORECASE):
                            vulnerabilities.append("{} detected: {}".format(vuln_type, match.group(0)))
                return vulnerabilities
        except Exception as e:
            self.stderr.println("Error detecting vulnerabilities: {}".format(str(e)))
        return []

    def __del__(self):
        """وقتی اکستنشن بسته می‌شه، Thread Pool رو هم خاموش کن"""
        self.threadPool.shutdown()

if __name__ == '__main__':
    pass