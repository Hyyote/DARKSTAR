using System;
using System.Drawing;
using System.Windows.Forms;

namespace DARKSTAR.UI.WinForms
{
    public sealed class MemoryCapWarningForm : Form
    {
        private readonly string _processDisplayName;
        private readonly int _memoryLimitMb;

        private CheckBox _confirmRestartCheckBox = null!;
        private CheckBox _dontShowAgainCheckBox = null!;
        private Button _cancelButton = null!;
        private Button _restartAndApplyButton = null!;

        public bool DontShowAgain => _dontShowAgainCheckBox.Checked;

        public MemoryCapWarningForm(string processDisplayName, int memoryLimitMb)
        {
            _processDisplayName = string.IsNullOrWhiteSpace(processDisplayName) ? "the target app" : processDisplayName.Trim();
            _memoryLimitMb = Math.Max(1, memoryLimitMb);

            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = "Memory Cap Warning";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Font;
            Font = new Font("Segoe UI", 9F);
            BackColor = SystemColors.Window;

            Width = 560;
            Height = 360;

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(14),
                ColumnCount = 1,
                RowCount = 6,
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var title = new Label
            {
                AutoSize = true,
                Font = new Font(Font, FontStyle.Bold),
                Text = "This action will restart the app to apply a hard memory cap",
                Margin = new Padding(0, 0, 0, 10),
            };

            var msg = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(510, 0),
                Text =
                    $"You are about to apply a memory cap of {_memoryLimitMb} MB to \"{_processDisplayName}\".\r\n\r\n" +
                    "To actually enforce a hard cap, DARKSTAR must launch the app inside a Windows Job object.\r\n" +
                    "That means the app must be restarted.",
                Margin = new Padding(0, 0, 0, 10),
            };

            var bullets = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(510, 0),
                Text =
                    "What to expect:\r\n" +
                    "• The app will be closed and restarted.\r\n" +
                    "• This is not a gentle throttle; when the cap is hit, the app may become unstable or crash.\r\n" +
                    "• Some apps are multi-process (e.g., browsers). The cap may affect child processes too.\r\n" +
                    "• If the app is already running, changes cannot be applied without restarting.",
                Margin = new Padding(0, 0, 0, 10),
            };

            _confirmRestartCheckBox = new CheckBox
            {
                AutoSize = true,
                Text = "I understand. Restart the app and apply the memory cap.",
                Margin = new Padding(0, 0, 0, 6),
            };

            _dontShowAgainCheckBox = new CheckBox
            {
                AutoSize = true,
                Text = "Don't show this warning again",
                Margin = new Padding(0, 0, 0, 10),
            };

            var buttonBar = new TableLayoutPanel
            {
                Dock = DockStyle.Bottom,
                ColumnCount = 3,
                RowCount = 1,
                Padding = new Padding(0),
                Margin = new Padding(0, 10, 0, 0),
            };
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                AutoSize = true,
                Height = 34,
                Padding = new Padding(16, 6, 16, 6),
                Margin = new Padding(0, 0, 10, 0),
            };

            _restartAndApplyButton = new Button
            {
                Text = "Restart && Apply Cap",
                DialogResult = DialogResult.OK,
                AutoSize = true,
                Height = 34,
                Padding = new Padding(16, 6, 16, 6),
                BackColor = Color.LightGoldenrodYellow,
                Margin = new Padding(0),
                Enabled = false
            };

            _confirmRestartCheckBox.CheckedChanged += (_, __) =>
            {
                _restartAndApplyButton.Enabled = _confirmRestartCheckBox.Checked;
            };

            buttonBar.Controls.Add(new Panel { Dock = DockStyle.Fill }, 0, 0);
            buttonBar.Controls.Add(_cancelButton, 1, 0);
            buttonBar.Controls.Add(_restartAndApplyButton, 2, 0);

            root.Controls.Add(title, 0, 0);
            root.Controls.Add(msg, 0, 1);
            root.Controls.Add(bullets, 0, 2);
            root.Controls.Add(_confirmRestartCheckBox, 0, 3);
            root.Controls.Add(_dontShowAgainCheckBox, 0, 4);
            root.Controls.Add(buttonBar, 0, 5);

            Controls.Add(root);

            CancelButton = _cancelButton;

            FormClosing += (_, e) =>
            {
                if (DialogResult == DialogResult.OK && !_confirmRestartCheckBox.Checked)
                {
                    DialogResult = DialogResult.Cancel;
                }
            };
        }

        public static DialogResult ShowDialog(IWin32Window owner, string processDisplayName, int memoryLimitMb, out bool dontShowAgain)
        {
            using var f = new MemoryCapWarningForm(processDisplayName, memoryLimitMb);
            var result = f.ShowDialog(owner);
            dontShowAgain = f.DontShowAgain;
            return result;
        }
    }
}
