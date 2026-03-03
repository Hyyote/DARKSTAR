using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace DARKSTAR.UI.WinForms
{
    public sealed class AddMemoryLimitFromRunningForm : Form
    {
        private readonly ImageList _icons = new ImageList
        {
            ImageSize = new Size(20, 20),
            ColorDepth = ColorDepth.Depth32Bit
        };

        private TextBox _searchBox = null!;
        private ListView _processList = null!;
        private NumericUpDown _limitMb = null!;
        private CheckBox _allowManualName = null!;
        private TextBox _manualNameBox = null!;
        private Button _refreshButton = null!;
        private Button _okButton = null!;
        private Button _cancelButton = null!;
        private Label _hintLabel = null!;

        private readonly Dictionary<string, int> _imageIndexByExe = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        public string SelectedExeName { get; private set; } = "";

        public int SelectedLimitMb { get; private set; }

        public AddMemoryLimitFromRunningForm(int defaultLimitMb = 2048)
        {
            InitializeComponent();
            _limitMb.Value = Math.Max((decimal)1, Math.Min(_limitMb.Maximum, defaultLimitMb));
            RefreshProcessList();
        }

        private void InitializeComponent()
        {
            Text = "Add Memory Limit — Select Running App";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            MaximizeBox = true;
            MinimumSize = new Size(720, 520);
            Size = new Size(900, 620);

            const int pad = 10;
            const int btnH = 34;

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(pad),
                ColumnCount = 1,
                RowCount = 6
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var topRow = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 2,
                RowCount = 1,
                AutoSize = true
            };
            topRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            topRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _searchBox = new TextBox
            {
                Dock = DockStyle.Top,
                PlaceholderText = "Search running processes… (name/exe)",
                Margin = new Padding(0, 0, pad, 0)
            };
            _searchBox.TextChanged += (_, __) => ApplyFilter();

            _refreshButton = new Button
            {
                Text = "Refresh",
                Height = btnH,
                AutoSize = true,
                Padding = new Padding(14, 6, 14, 6)
            };
            _refreshButton.Click += (_, __) => RefreshProcessList();

            topRow.Controls.Add(_searchBox, 0, 0);
            topRow.Controls.Add(_refreshButton, 1, 0);

            _hintLabel = new Label
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                ForeColor = Color.DimGray,
                Text = "Select a running app on the left. If it is not running, enable manual name entry below."
            };

            _processList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                HideSelection = false,
                SmallImageList = _icons
            };
            _processList.Columns.Add("App (exe)", 240);
            _processList.Columns.Add("PID", 90);
            _processList.Columns.Add("Memory", 120);
            _processList.Columns.Add("Title", 360);

            _processList.SelectedIndexChanged += (_, __) => SyncOkEnabled();
            _processList.DoubleClick += (_, __) =>
            {
                if (_processList.SelectedItems.Count > 0)
                    SaveAndCloseOk();
            };

            var limitRow = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 3,
                RowCount = 1,
                AutoSize = true
            };
            limitRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            limitRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            limitRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var limitLbl = new Label
            {
                Text = "Memory limit (MB):",
                AutoSize = true,
                Anchor = AnchorStyles.Left
            };

            _limitMb = new NumericUpDown
            {
                Minimum = 1,
                Maximum = 1024 * 1024,
                Value = 2048,
                Width = 140,
                Anchor = AnchorStyles.Left
            };

            var limitHint = new Label
            {
                Text = "Tip: Configure the limit here, then apply it using \"Restart && Apply Memory Cap\" in the Global tab (hard cap requires restart).",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Anchor = AnchorStyles.Left
            };

            limitRow.Controls.Add(limitLbl, 0, 0);
            limitRow.Controls.Add(_limitMb, 1, 0);
            limitRow.Controls.Add(limitHint, 2, 0);

            var manualRow = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 3,
                RowCount = 1,
                AutoSize = true
            };
            manualRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            manualRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            manualRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _allowManualName = new CheckBox
            {
                Text = "Manual name:",
                AutoSize = true,
                Anchor = AnchorStyles.Left
            };
            _allowManualName.CheckedChanged += (_, __) =>
            {
                _manualNameBox.Enabled = _allowManualName.Checked;
                if (!_allowManualName.Checked)
                    _manualNameBox.Text = "";
                SyncOkEnabled();
            };

            _manualNameBox = new TextBox
            {
                Dock = DockStyle.Top,
                Enabled = false,
                PlaceholderText = "example.exe or example (will be normalized to .exe)"
            };
            _manualNameBox.TextChanged += (_, __) => SyncOkEnabled();

            var manualHint = new Label
            {
                Text = "Use when app is not running",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Anchor = AnchorStyles.Left
            };

            manualRow.Controls.Add(_allowManualName, 0, 0);
            manualRow.Controls.Add(_manualNameBox, 1, 0);
            manualRow.Controls.Add(manualHint, 2, 0);

            var buttons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                WrapContents = false,
                Padding = new Padding(0, pad, 0, 0)
            };

            _okButton = new Button
            {
                Text = "Add",
                Height = btnH,
                AutoSize = true,
                Padding = new Padding(16, 6, 16, 6),
                Enabled = false
            };
            _okButton.Click += (_, __) => SaveAndCloseOk();

            _cancelButton = new Button
            {
                Text = "Cancel",
                Height = btnH,
                AutoSize = true,
                Padding = new Padding(16, 6, 16, 6)
            };
            _cancelButton.Click += (_, __) => { DialogResult = DialogResult.Cancel; Close(); };

            AcceptButton = _okButton;
            CancelButton = _cancelButton;

            buttons.Controls.Add(_okButton);
            buttons.Controls.Add(_cancelButton);

            root.Controls.Add(topRow, 0, 0);
            root.Controls.Add(_hintLabel, 0, 1);
            root.Controls.Add(_processList, 0, 2);
            root.Controls.Add(limitRow, 0, 3);
            root.Controls.Add(manualRow, 0, 4);
            root.Controls.Add(buttons, 0, 5);

            Controls.Add(root);
        }

        private void RefreshProcessList()
        {
            _processList.BeginUpdate();
            try
            {
                _processList.Items.Clear();

                var processes = Process.GetProcesses()
                    .Where(p =>
                    {
                        try { return !string.IsNullOrWhiteSpace(p.ProcessName); }
                        catch { return false; }
                    })
                    .OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var p in processes)
                {
                    string exe = NormalizeExeKey(p.ProcessName);
                    int pid = 0;
                    long ws = 0;
                    string title = "";

                    try { pid = p.Id; } catch { }
                    try { ws = p.WorkingSet64; } catch { }
                    try { title = p.MainWindowTitle ?? ""; } catch { }

                    int imageIndex = EnsureIcon(exe, p);

                    var item = new ListViewItem(exe, imageIndex);
                    item.SubItems.Add(pid.ToString());
                    item.SubItems.Add(ws > 0 ? $"{ws / 1024 / 1024} MB" : "");
                    item.SubItems.Add(title);

                    item.Tag = exe;
                    _processList.Items.Add(item);
                }

                ApplyFilter();
            }
            finally
            {
                _processList.EndUpdate();
            }
        }

        private void ApplyFilter()
        {
            string q = (_searchBox.Text ?? "").Trim();
            if (string.IsNullOrEmpty(q))
            {
                foreach (ListViewItem it in _processList.Items)
                    it.ForeColor = SystemColors.WindowText;

                SyncOkEnabled();
                return;
            }

            foreach (ListViewItem it in _processList.Items)
            {
                string exe = it.Text ?? "";
                bool match = exe.Contains(q, StringComparison.OrdinalIgnoreCase)
                             || it.SubItems.Cast<ListViewItem.ListViewSubItem>()
                                 .Any(s => (s.Text ?? "").Contains(q, StringComparison.OrdinalIgnoreCase));

                it.ForeColor = match ? SystemColors.WindowText : Color.LightGray;
            }

            SyncOkEnabled();
        }

        private void SyncOkEnabled()
        {
            bool hasRuntimeSelection = _processList.SelectedItems.Count > 0;
            bool hasManual = _allowManualName.Checked && !string.IsNullOrWhiteSpace(_manualNameBox.Text);

            _okButton.Enabled = hasRuntimeSelection || hasManual;
        }

        private void SaveAndCloseOk()
        {
            string exe;
            if (_allowManualName.Checked && !string.IsNullOrWhiteSpace(_manualNameBox.Text))
            {
                exe = NormalizeExeKey(_manualNameBox.Text.Trim());
            }
            else if (_processList.SelectedItems.Count > 0)
            {
                exe = _processList.SelectedItems[0].Text ?? "";
                exe = NormalizeExeKey(exe);
            }
            else
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(exe))
                return;

            SelectedExeName = exe;
            SelectedLimitMb = (int)_limitMb.Value;

            DialogResult = DialogResult.OK;
            Close();
        }

        private int EnsureIcon(string exeKey, Process? process)
        {
            if (_imageIndexByExe.TryGetValue(exeKey, out int idx))
                return idx;

            try
            {
                if (process != null)
                {
                    string? path = null;
                    try { path = process.MainModule?.FileName; } catch { }
                    if (!string.IsNullOrEmpty(path))
                    {
                        using var ico = Icon.ExtractAssociatedIcon(path);
                        if (ico != null)
                        {
                            _icons.Images.Add(exeKey, ico.ToBitmap());
                            idx = _icons.Images.IndexOfKey(exeKey);
                            _imageIndexByExe[exeKey] = idx;
                            return idx;
                        }
                    }
                }
            }
            catch
            {
            }

            try
            {
                _icons.Images.Add(exeKey, SystemIcons.Application.ToBitmap());
                idx = _icons.Images.IndexOfKey(exeKey);
                _imageIndexByExe[exeKey] = idx;
                return idx;
            }
            catch
            {
                _icons.Images.Add(exeKey, new Bitmap(_icons.ImageSize.Width, _icons.ImageSize.Height));
                idx = _icons.Images.IndexOfKey(exeKey);
                _imageIndexByExe[exeKey] = idx;
                return idx;
            }
        }

        private static string NormalizeExeKey(string nameOrExe)
        {
            if (string.IsNullOrWhiteSpace(nameOrExe))
                return "";

            var s = nameOrExe.Trim();

            if (!s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                s += ".exe";

            return s;
        }
    }
}
