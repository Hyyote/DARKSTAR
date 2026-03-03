using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Windows.Forms;
using DARKSTAR.Core;
using DARKSTAR.Features;
using DARKSTAR.UI.WinForms.Native;

namespace DARKSTAR.UI.WinForms
{
    public sealed class ProcessDetailForm : Form
    {
        private readonly int _processId;
        private readonly string _processName;
        private readonly bool _isGameProfile;

        private int _resolvedRuntimePid;

        private readonly Dictionary<string, ProcessConfig> _gameConfigs;
        private readonly Dictionary<string, ProcessConfig> _systemConfigs;

        private readonly ProcessConfig _config;

        private bool _runtimeModulesAvailable;
        private bool _runtimeThreadsAvailable;

        private string? _lastCoreClassSelection;

        private TabControl _tabs = null!;

        private ComboBox _affinityCombo = null!;
        private TextBox _affinityMaskTextBox = null!;
        private Button _affinityPickButton = null!;
        private CheckBox _disableBoostCheckBox = null!;
        private ComboBox _gpuPriorityCombo = null!;
        private Button _applyProcessSettingsButton = null!;

        private SplitContainer _modulesSplit = null!;
        private ListView _runtimeModulesList = null!;
        private ListView _configuredModulesList = null!;
        private Button _refreshModulesButton = null!;
        private Button _addModuleRuleButton = null!;
        private Button _editModuleRuleButton = null!;
        private Button _removeModuleRuleButton = null!;
        private Button _addModuleRuleManualButton = null!;

        private SplitContainer _threadsSplit = null!;
        private ListView _runtimeThreadsList = null!;
        private ListView _configuredThreadsList = null!;
        private Button _refreshThreadsButton = null!;
        private Button _addThreadRuleButton = null!;
        private Button _editThreadRuleButton = null!;
        private Button _removeThreadRuleButton = null!;
        private Button _addThreadRuleManualButton = null!;

        private Button _saveButton = null!;
        private Button _cancelButton = null!;
        private Label _statusLabel = null!;

        private const int UiPad = 10;
        private const int ButtonHeight = 34;
        private const int TextBoxHeight = 26;

        public ProcessDetailForm(
            int processId,
            string processName,
            bool isGameProfile,
            Dictionary<string, ProcessConfig> gameConfigs,
            Dictionary<string, ProcessConfig> systemConfigs,
            ProcessConfig config)
        {
            if (string.IsNullOrWhiteSpace(processName))
                throw new ArgumentException("processName is required", nameof(processName));

            _processId = processId;
            _processName = processName;
            _isGameProfile = isGameProfile;
            _gameConfigs = gameConfigs ?? throw new ArgumentNullException(nameof(gameConfigs));
            _systemConfigs = systemConfigs ?? throw new ArgumentNullException(nameof(systemConfigs));
            _config = config ?? throw new ArgumentNullException(nameof(config));

            InitializeComponent();
            LoadFromConfigToUi();
            RefreshConfiguredLists();

            _resolvedRuntimePid = ResolveRunningPidFromProcessName();

            int runtimePid = _processId > 0 ? _processId : _resolvedRuntimePid;

            if (runtimePid > 0)
            {
                RefreshRuntimeModules(runtimePid);
                RefreshRuntimeThreads(runtimePid);
            }
            else
            {
                _runtimeModulesAvailable = false;
                _runtimeThreadsAvailable = false;

                _runtimeModulesList.Items.Clear();
                _runtimeModulesList.Items.Add(new ListViewItem("⚠ Runtime modules not available (process not running). Add module rules manually."));

                _runtimeThreadsList.Items.Clear();
                _runtimeThreadsList.Items.Add(new ListViewItem("⚠ Runtime threads not available (process not running). Add thread rules manually."));
            }

            UpdateRuntimeUiAvailability();
        }

        private void InitializeComponent()
        {
            Text = $"DARKSTAR Editor — {_processName} (PID {_processId})";
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 600);
            Size = new Size(1100, 720);

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(UiPad),
            };
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _tabs = new TabControl { Dock = DockStyle.Fill };

            var tabProcess = new TabPage("Process Settings");
            var tabModules = new TabPage("Modules");
            var tabThreads = new TabPage("Threads");

            BuildProcessSettingsTab(tabProcess);
            BuildModulesTab(tabModules);
            BuildThreadsTab(tabThreads);

            _tabs.TabPages.Add(tabProcess);
            _tabs.TabPages.Add(tabModules);
            _tabs.TabPages.Add(tabThreads);

            var footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                WrapContents = false,
                Padding = new Padding(0, UiPad, 0, 0),
            };

            _saveButton = new Button
            {
                Text = "Save",
                Height = ButtonHeight,
                AutoSize = true,
                Padding = new Padding(16, 6, 16, 6),
                BackColor = Color.LightGreen
            };
            _saveButton.Click += (_, __) => SaveAndClose();

            _cancelButton = new Button
            {
                Text = "Cancel",
                Height = ButtonHeight,
                AutoSize = true,
                Padding = new Padding(16, 6, 16, 6),
            };
            _cancelButton.Click += (_, __) => { DialogResult = DialogResult.Cancel; Close(); };

            footer.Controls.Add(_saveButton);
            footer.Controls.Add(_cancelButton);

            _statusLabel = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                Text = "Ready",
                ForeColor = Color.DimGray,
                Padding = new Padding(0, 6, 0, 0),
            };

            root.Controls.Add(_tabs, 0, 0);
            root.Controls.Add(footer, 0, 1);
            root.Controls.Add(_statusLabel, 0, 2);

            Controls.Add(root);
        }

        private void BuildProcessSettingsTab(TabPage tab)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 7,
                Padding = new Padding(UiPad),
            };

            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            layout.Controls.Add(new Label { Text = "Priority:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);

            var priCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 260,
                Anchor = AnchorStyles.Left,
            };

            var priorities = ConfigLoader.PriorityMap
                .Where(kv => kv.Key is 15 or 2 or 1 or 0 or -1 or -2 or -15)
                .OrderByDescending(kv => kv.Key)
                .Select(kv => new PriorityChoice(kv.Key, kv.Value))
                .ToList();

            if (priorities.Count == 0)
            {
                priorities.AddRange(new[]
                {
                    new PriorityChoice(15, "TIME_CRITICAL"),
                    new PriorityChoice(2, "HIGHEST"),
                    new PriorityChoice(1, "ABOVE_NORMAL"),
                    new PriorityChoice(0, "NORMAL"),
                    new PriorityChoice(-1, "BELOW_NORMAL"),
                    new PriorityChoice(-2, "LOWEST"),
                    new PriorityChoice(-15, "IDLE"),
                });
            }

            priCombo.Items.AddRange(priorities.Cast<object>().ToArray());
            tab.Tag = priCombo;

            layout.Controls.Add(priCombo, 1, 0);

            layout.Controls.Add(new Label { Text = "Affinity preset:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
            _affinityCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 220,
                Anchor = AnchorStyles.Left,
            };

            _affinityCombo.Items.AddRange(new object[] { "ALL", "P-CORE", "E-CORE", "HT ON", "HT OFF", "MANUAL" });
            _affinityCombo.SelectedIndexChanged += (_, __) =>
            {
                var choice = _affinityCombo.SelectedItem?.ToString() ?? "ALL";

                if (string.Equals(choice, "ALL", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(choice, "P-CORE", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(choice, "E-CORE", StringComparison.OrdinalIgnoreCase))
                {
                    _lastCoreClassSelection = choice;
                }

                bool manual = string.Equals(choice, "MANUAL", StringComparison.OrdinalIgnoreCase);

                _affinityMaskTextBox.Enabled = manual;
                _affinityPickButton.Enabled = manual;

                if (manual)
                {
                    using var picker = new CpuAffinityPickerForm(cpuCount: Environment.ProcessorCount, initialMaskHex: _affinityMaskTextBox.Text);
                    if (picker.ShowDialog(this) == DialogResult.OK)
                    {
                        _affinityMaskTextBox.Text = picker.SelectedHexMask;
                    }
                }
                else
                {
                    _affinityMaskTextBox.Text = choice;
                }
            };
            layout.Controls.Add(_affinityCombo, 1, 1);

            layout.Controls.Add(new Label { Text = "Affinity mask:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
            _affinityMaskTextBox = new TextBox
            {
                Height = TextBoxHeight,
                Width = 240,
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                Enabled = false,
            };
            layout.Controls.Add(_affinityMaskTextBox, 1, 2);

            _affinityPickButton = new Button
            {
                Text = "Pick…",
                Height = ButtonHeight,
                AutoSize = true,
                Enabled = false,
                Anchor = AnchorStyles.Left,
            };
            _affinityPickButton.Click += (_, __) =>
            {
                using var picker = new CpuAffinityPickerForm(cpuCount: Environment.ProcessorCount, initialMaskHex: _affinityMaskTextBox.Text);
                if (picker.ShowDialog(this) == DialogResult.OK)
                {
                    _affinityMaskTextBox.Text = picker.SelectedHexMask;
                }
            };
            layout.Controls.Add(_affinityPickButton, 2, 2);

            layout.Controls.Add(new Label { Text = "Priority boost:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
            _disableBoostCheckBox = new CheckBox
            {
                Text = "Disable Priority Boost",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
            };
            layout.Controls.Add(_disableBoostCheckBox, 1, 3);

            layout.Controls.Add(new Label { Text = "GPU Priority:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 4);
            _gpuPriorityCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 220,
                Anchor = AnchorStyles.Left,
            };
            _gpuPriorityCombo.Items.AddRange(new object[] { "None", "Very Low", "Low", "Normal", "High" });
            _gpuPriorityCombo.SelectedIndex = 0;
            layout.Controls.Add(_gpuPriorityCombo, 1, 4);

            _applyProcessSettingsButton = new Button
            {
                Text = "Apply to Config (not runtime)",
                Height = ButtonHeight,
                AutoSize = true,
                Padding = new Padding(16, 6, 16, 6),
                BackColor = Color.LightBlue,
                Anchor = AnchorStyles.Left,
            };
            _applyProcessSettingsButton.Click += (_, __) =>
            {
                SaveProcessSettingsIntoConfig();
                RefreshConfiguredLists();
                SetStatus("Process settings updated in config.");
            };
            layout.Controls.Add(_applyProcessSettingsButton, 1, 6);

            tab.Controls.Add(layout);
        }

        private void BuildModulesTab(TabPage tab)
        {
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Padding = new Padding(UiPad),
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var header = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = false,
            };

            _refreshModulesButton = new Button
            {
                Text = "Refresh Runtime Modules",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _refreshModulesButton.Click += (_, __) =>
            {
                _resolvedRuntimePid = ResolveRunningPidFromProcessName();
                int runtimePid = _processId > 0 ? _processId : _resolvedRuntimePid;
                RefreshRuntimeModules(runtimePid);
            };

            _addModuleRuleButton = new Button
            {
                Text = "Add Rule (from runtime)",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _addModuleRuleButton.Click += (_, __) => AddModuleRuleFromSelection();

            _addModuleRuleManualButton = new Button
            {
                Text = "Add Rule (manual)",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _addModuleRuleManualButton.Click += (_, __) => AddModuleRuleManual();

            _editModuleRuleButton = new Button
            {
                Text = "Edit Rule",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _editModuleRuleButton.Click += (_, __) => EditSelectedModuleRule();

            _removeModuleRuleButton = new Button
            {
                Text = "Remove Rule",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _removeModuleRuleButton.Click += (_, __) => RemoveSelectedModuleRule();

            header.Controls.AddRange(new Control[]
            {
                _refreshModulesButton,
                _addModuleRuleButton,
                _addModuleRuleManualButton,
                _editModuleRuleButton,
                _removeModuleRuleButton
            });

            _modulesSplit = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                SplitterWidth = 6,
                FixedPanel = FixedPanel.None,
            };

            _runtimeModulesList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
            };
            _runtimeModulesList.Columns.Add("Runtime modules (loaded now)", 320);
            _runtimeModulesList.Columns.Add("Path", 520);

            _configuredModulesList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
            };
            _configuredModulesList.Columns.Add("Configured module rule", 320);
            _configuredModulesList.Columns.Add("Priority", 100);

            _modulesSplit.Panel1.Controls.Add(_runtimeModulesList);
            _modulesSplit.Panel2.Controls.Add(_configuredModulesList);

            root.Controls.Add(header, 0, 0);
            root.Controls.Add(_modulesSplit, 0, 1);

            tab.Controls.Add(root);
        }

        private void BuildThreadsTab(TabPage tab)
        {
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Padding = new Padding(UiPad),
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var header = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = false,
            };

            _refreshThreadsButton = new Button
            {
                Text = "Refresh Runtime Threads",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _refreshThreadsButton.Click += (_, __) =>
            {
                _resolvedRuntimePid = ResolveRunningPidFromProcessName();
                int runtimePid = _processId > 0 ? _processId : _resolvedRuntimePid;
                RefreshRuntimeThreads(runtimePid);
            };

            _addThreadRuleButton = new Button
            {
                Text = "Add Rule (from runtime)",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _addThreadRuleButton.Click += (_, __) => AddThreadRuleFromSelection();

            _addThreadRuleManualButton = new Button
            {
                Text = "Add Rule (manual)",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _addThreadRuleManualButton.Click += (_, __) => AddThreadRuleManual();

            _editThreadRuleButton = new Button
            {
                Text = "Edit Rule",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _editThreadRuleButton.Click += (_, __) => EditSelectedThreadRule();

            _removeThreadRuleButton = new Button
            {
                Text = "Remove Rule",
                Height = ButtonHeight,
                AutoSize = true,
            };
            _removeThreadRuleButton.Click += (_, __) => RemoveSelectedThreadRule();

            header.Controls.AddRange(new Control[]
            {
                _refreshThreadsButton,
                _addThreadRuleButton,
                _addThreadRuleManualButton,
                _editThreadRuleButton,
                _removeThreadRuleButton
            });

            _threadsSplit = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                SplitterWidth = 6,
                FixedPanel = FixedPanel.None,
            };

            _runtimeThreadsList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
            };
            _runtimeThreadsList.Columns.Add("Name", 220);
            _runtimeThreadsList.Columns.Add("TID", 90);
            _runtimeThreadsList.Columns.Add("Start Address", 140);
            _runtimeThreadsList.Columns.Add("State", 120);
            _runtimeThreadsList.Columns.Add("Wait", 120);

            _configuredThreadsList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
            };
            _configuredThreadsList.Columns.Add("Configured thread rule", 240);
            _configuredThreadsList.Columns.Add("Priority", 100);
            _configuredThreadsList.Columns.Add("Affinity", 140);
            _configuredThreadsList.Columns.Add("Disable Boost", 120);

            _threadsSplit.Panel1.Controls.Add(_runtimeThreadsList);
            _threadsSplit.Panel2.Controls.Add(_configuredThreadsList);

            root.Controls.Add(header, 0, 0);
            root.Controls.Add(_threadsSplit, 0, 1);

            tab.Controls.Add(root);
        }

        private void LoadFromConfigToUi()
        {
            if (_tabs.TabPages.Count > 0 && _tabs.TabPages[0].Tag is ComboBox priCombo)
            {
                var found = priCombo.Items
                    .Cast<object>()
                    .OfType<PriorityChoice>()
                    .FirstOrDefault(p => p.Value == _config.Priority);

                if (found != null)
                    priCombo.SelectedItem = found;
                else
                {
                    var normal = priCombo.Items
                        .Cast<object>()
                        .OfType<PriorityChoice>()
                        .FirstOrDefault(p => p.Value == 0);

                    if (normal != null)
                        priCombo.SelectedItem = normal;
                    else if (priCombo.Items.Count > 0)
                        priCombo.SelectedIndex = 0;
                }
            }

            _disableBoostCheckBox.Checked = _config.DisableBoost;

            _gpuPriorityCombo.SelectedIndex = _config.GpuPriority switch
            {
                GpuPriority.VeryLow => 1,
                GpuPriority.Low => 2,
                GpuPriority.Normal => 3,
                GpuPriority.High => 4,
                _ => 0
            };

            var aff = (_config.Affinity ?? "ALL").Trim();
            if (string.IsNullOrWhiteSpace(aff))
                aff = "ALL";

            var known = new[] { "ALL", "P-CORE", "E-CORE", "HT ON", "HT OFF", "AUTO", "MANUAL" };
            var match = known.FirstOrDefault(x => string.Equals(x, aff, StringComparison.OrdinalIgnoreCase));

            if (match != null && !string.Equals(match, "MANUAL", StringComparison.OrdinalIgnoreCase))
            {
                _affinityCombo.SelectedItem = match;
                _affinityMaskTextBox.Text = match;
                _affinityMaskTextBox.Enabled = false;
                _affinityPickButton.Enabled = false;
            }
            else
            {
                _affinityCombo.SelectedItem = "MANUAL";
                _affinityMaskTextBox.Text = aff;
                _affinityMaskTextBox.Enabled = true;
                _affinityPickButton.Enabled = true;
            }

            if (_affinityCombo.SelectedItem == null)
                _affinityCombo.SelectedItem = "ALL";
        }

        private void SaveProcessSettingsIntoConfig()
        {
            if (_tabs.TabPages.Count > 0 && _tabs.TabPages[0].Tag is ComboBox priCombo)
            {
                if (priCombo.SelectedItem is PriorityChoice pc)
                    _config.Priority = pc.Value;
                else
                    _config.Priority = 0;
            }
            else
            {
                _config.Priority = 0;
            }

            _config.DisableBoost = _disableBoostCheckBox.Checked;

            var gpuPriorityText = _gpuPriorityCombo.SelectedItem?.ToString() ?? "None";
            _config.GpuPriority = gpuPriorityText.ToLowerInvariant().Replace(" ", "_") switch
            {
                "very_low" => GpuPriority.VeryLow,
                "low" => GpuPriority.Low,
                "normal" => GpuPriority.Normal,
                "high" => GpuPriority.High,
                _ => GpuPriority.None
            };

            var choice = _affinityCombo.SelectedItem?.ToString() ?? "ALL";

            if (string.Equals(choice, "MANUAL", StringComparison.OrdinalIgnoreCase))
            {
                var hex = (_affinityMaskTextBox.Text ?? "0x0").Trim();
                if (!hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    hex = "0x" + hex;
                _config.Affinity = hex;
                return;
            }

            if (string.Equals(choice, "HT ON", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(choice, "HT OFF", StringComparison.OrdinalIgnoreCase))
            {
                string targetClass;
                if (string.Equals(_lastCoreClassSelection, "P-CORE", StringComparison.OrdinalIgnoreCase))
                    targetClass = "ALL";
                else if (string.Equals(_lastCoreClassSelection, "E-CORE", StringComparison.OrdinalIgnoreCase))
                    targetClass = "E-CORE";
                else
                    targetClass = "P-CORE";

                var mask = ComputeTopologyBasedHtMask(choice, targetClass);
                _config.Affinity = ToHex(mask);
                return;
            }

            if (string.Equals(choice, "P-CORE", StringComparison.OrdinalIgnoreCase))
            {
                var mask = ComputeTopologyBasedHtMask("HT ON", "P-CORE");
                _config.Affinity = ToHex(mask);
                return;
            }

            if (string.Equals(choice, "E-CORE", StringComparison.OrdinalIgnoreCase))
            {
                var mask = ComputeTopologyBasedHtMask("HT ON", "E-CORE");
                _config.Affinity = ToHex(mask);
                return;
            }

            _config.Affinity = choice;
        }

        private void RefreshConfiguredLists()
        {
            _configuredModulesList.Items.Clear();
            foreach (var kv in _config.Modules.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var item = new ListViewItem(kv.Key);
                item.SubItems.Add(kv.Value.ToString());
                item.Tag = kv.Key;
                _configuredModulesList.Items.Add(item);
            }

            _configuredThreadsList.Items.Clear();
            foreach (var kv in _config.Threads.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var item = new ListViewItem(kv.Key);
                item.SubItems.Add(kv.Value.Priority.ToString());
                item.SubItems.Add((kv.Value.Affinity ?? "ALL").Trim());
                item.SubItems.Add(kv.Value.DisableBoost.ToString());
                item.Tag = kv.Key;
                _configuredThreadsList.Items.Add(item);
            }
        }

        private void RefreshRuntimeModules(int runtimePid)
        {
            _runtimeModulesList.Items.Clear();

            if (runtimePid <= 0)
            {
                _resolvedRuntimePid = ResolveRunningPidFromProcessName();
                runtimePid = _processId > 0 ? _processId : _resolvedRuntimePid;
            }

            if (runtimePid <= 0)
            {
                _runtimeModulesAvailable = false;
                _runtimeModulesList.Items.Add(new ListViewItem("⚠ Runtime modules not available (process not running). Add module rules manually."));
                return;
            }

            try
            {
                using var p = Process.GetProcessById(runtimePid);

                int count = 0;
                foreach (ProcessModule m in p.Modules)
                {
                    var name = m.ModuleName ?? "(unknown)";
                    var path = m.FileName ?? string.Empty;

                    var item = new ListViewItem(name);
                    item.SubItems.Add(path);
                    item.Tag = name;
                    _runtimeModulesList.Items.Add(item);
                    count++;
                }

                _runtimeModulesAvailable = true;
                SetStatus($"Runtime modules loaded: {count}");
            }
            catch (Exception ex)
            {
                _runtimeModulesAvailable = false;
                SetStatus($"Runtime modules not available: {ex.Message}");
                _runtimeModulesList.Items.Add(new ListViewItem("⚠ Runtime modules not available (process not running / protected / access denied)."));
            }
        }

        private void RefreshRuntimeThreads(int runtimePid)
        {
            _runtimeThreadsList.Items.Clear();

            if (runtimePid <= 0)
            {
                _resolvedRuntimePid = ResolveRunningPidFromProcessName();
                runtimePid = _processId > 0 ? _processId : _resolvedRuntimePid;
            }

            if (runtimePid <= 0)
            {
                _runtimeThreadsAvailable = false;
                _runtimeThreadsList.Items.Add(new ListViewItem("⚠ Runtime threads not available (process not running). Add thread rules manually."));
                return;
            }

            try
            {
                using var p = Process.GetProcessById(runtimePid);

                int count = 0;
                foreach (ProcessThread t in p.Threads)
                {
                    string name = "";
                    string start = "";
                    string state = t.ThreadState.ToString();
                    string wait = (t.ThreadState == System.Diagnostics.ThreadState.Wait) ? t.WaitReason.ToString() : "";

                    if (ThreadNative.TryGetThreadDescription(t.Id, out var desc, out _))
                        name = desc ?? "";

                    if (ThreadNative.TryGetWin32StartAddress(t.Id, out var addr, out _))
                        start = $"0x{addr:X}";

                    var item = new ListViewItem(name);
                    item.SubItems.Add(t.Id.ToString());
                    item.SubItems.Add(start);
                    item.SubItems.Add(state);
                    item.SubItems.Add(wait);
                    item.Tag = t.Id;
                    _runtimeThreadsList.Items.Add(item);
                    count++;
                }

                _runtimeThreadsAvailable = true;
                SetStatus($"Runtime threads loaded: {count}");
            }
            catch (Exception ex)
            {
                _runtimeThreadsAvailable = false;
                SetStatus($"Runtime threads not available: {ex.Message}");
                _runtimeThreadsList.Items.Add(new ListViewItem("⚠ Runtime threads not available (process not running / protected / access denied)."));
            }
        }

        private void AddModuleRuleFromSelection()
        {
            if (!_runtimeModulesAvailable)
            {
                MessageBox.Show("Runtime modules are not available. Use 'Add Rule (manual)'.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string? moduleName = null;

            if (_runtimeModulesList.SelectedItems.Count > 0)
                moduleName = _runtimeModulesList.SelectedItems[0].Text;

            if (string.IsNullOrWhiteSpace(moduleName))
            {
                MessageBox.Show("Select a runtime module first, or use 'Add Rule (manual)'.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            AddModuleRuleInternal(moduleName.Trim());
        }

        private void AddModuleRuleManual()
        {
            var moduleName = PromptText("Add Module Rule", "Module name (e.g. game.dll):");
            if (string.IsNullOrWhiteSpace(moduleName)) return;
            AddModuleRuleInternal(moduleName.Trim());
        }

        private void AddModuleRuleInternal(string moduleName)
        {
            if (_config.Modules.ContainsKey(moduleName))
            {
                MessageBox.Show("Module rule already exists.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            int? pri = PromptInt("Module Priority", "Priority value (int):", 0);
            if (pri == null) return;

            _config.Modules[moduleName] = pri.Value;
            RefreshConfiguredLists();
            SetStatus($"Added module rule: {moduleName}");
        }

        private void EditSelectedModuleRule()
        {
            if (_configuredModulesList.SelectedItems.Count == 0) return;
            var key = _configuredModulesList.SelectedItems[0].Text;

            if (!_config.Modules.TryGetValue(key, out var existing))
                return;

            int? pri = PromptInt("Edit Module Priority", $"Priority for {key}:", existing);
            if (pri == null) return;

            _config.Modules[key] = pri.Value;
            RefreshConfiguredLists();
            SetStatus($"Updated module rule: {key}");
        }

        private void RemoveSelectedModuleRule()
        {
            if (_configuredModulesList.SelectedItems.Count == 0) return;
            var key = _configuredModulesList.SelectedItems[0].Text;

            if (MessageBox.Show($"Remove module rule '{key}'?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            _config.Modules.Remove(key);
            RefreshConfiguredLists();
            SetStatus($"Removed module rule: {key}");
        }

        private void AddThreadRuleFromSelection()
        {
            if (!_runtimeThreadsAvailable)
            {
                MessageBox.Show("Runtime threads are not available. Use 'Add Rule (manual)'.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string? threadKey = null;

            if (_runtimeThreadsList.SelectedItems.Count > 0 && _runtimeThreadsList.SelectedItems[0].SubItems.Count > 1)
            {
                var tid = _runtimeThreadsList.SelectedItems[0].SubItems[1].Text;
                if (!string.IsNullOrWhiteSpace(tid))
                    threadKey = tid.Trim();
            }

            if (string.IsNullOrWhiteSpace(threadKey))
            {
                MessageBox.Show("Select a runtime thread first, or use 'Add Rule (manual)'.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            AddThreadRuleInternal(threadKey);
        }

        private void AddThreadRuleManual()
        {
            var threadKey = PromptText("Add Thread Rule", "Thread identifier (TID or configured name):");
            if (string.IsNullOrWhiteSpace(threadKey)) return;
            AddThreadRuleInternal(threadKey.Trim());
        }

        private void AddThreadRuleInternal(string threadKey)
        {
            if (_config.Threads.ContainsKey(threadKey))
            {
                MessageBox.Show("Thread rule already exists.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var cfg = new ThreadConfig
            {
                Priority = 0,
                Affinity = "ALL",
                DisableBoost = false
            };

            if (!EditThreadConfigDialog(threadKey, cfg))
                return;

            _config.Threads[threadKey] = cfg;
            RefreshConfiguredLists();
            SetStatus($"Added thread rule: {threadKey}");
        }

        private void EditSelectedThreadRule()
        {
            if (_configuredThreadsList.SelectedItems.Count == 0) return;
            var key = _configuredThreadsList.SelectedItems[0].Text;

            if (!_config.Threads.TryGetValue(key, out var cfg))
                return;

            var clone = new ThreadConfig { Priority = cfg.Priority, Affinity = cfg.Affinity, DisableBoost = cfg.DisableBoost };
            if (!EditThreadConfigDialog(key, clone))
                return;

            cfg.Priority = clone.Priority;
            cfg.Affinity = clone.Affinity;
            cfg.DisableBoost = clone.DisableBoost;

            RefreshConfiguredLists();
            SetStatus($"Updated thread rule: {key}");
        }

        private void RemoveSelectedThreadRule()
        {
            if (_configuredThreadsList.SelectedItems.Count == 0) return;
            var key = _configuredThreadsList.SelectedItems[0].Text;

            if (MessageBox.Show($"Remove thread rule '{key}'?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            _config.Threads.Remove(key);
            RefreshConfiguredLists();
            SetStatus($"Removed thread rule: {key}");
        }

        private void SaveAndClose()
        {
            SaveProcessSettingsIntoConfig();

            var target = _isGameProfile ? _gameConfigs : _systemConfigs;
            target[_processName] = _config;

            DialogResult = DialogResult.OK;
            Close();
        }

        private void SetStatus(string text)
        {
            _statusLabel.Text = text;
        }

        private void UpdateRuntimeUiAvailability()
        {
            _addModuleRuleButton.Enabled = _runtimeModulesAvailable;
            _refreshModulesButton.Enabled = true;
            _addModuleRuleManualButton.Enabled = true;

            _addThreadRuleButton.Enabled = _runtimeThreadsAvailable;
            _refreshThreadsButton.Enabled = true;
            _addThreadRuleManualButton.Enabled = true;
        }

        private static int Clamp(int value, int min, int max)
            => value < min ? min : (value > max ? max : value);

        private static string? PromptText(string title, string message)
        {
            using var f = new Form
            {
                Text = title,
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MinimizeBox = false,
                MaximizeBox = false,
                Width = 520,
                Height = 180
            };

            var lbl = new Label { Text = message, AutoSize = true, Left = 12, Top = 12 };
            var tb = new TextBox { Left = 12, Top = 40, Width = 480 };

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Left = 312, Width = 80, Top = 80 };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Left = 412, Width = 80, Top = 80 };

            f.AcceptButton = ok;
            f.CancelButton = cancel;

            f.Controls.AddRange(new Control[] { lbl, tb, ok, cancel });

            return f.ShowDialog() == DialogResult.OK ? tb.Text?.Trim() : null;
        }

        private static int? PromptInt(string title, string message, int defaultValue)
        {
            using var f = new Form
            {
                Text = title,
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MinimizeBox = false,
                MaximizeBox = false,
                Width = 520,
                Height = 200
            };

            var lbl = new Label { Text = message, AutoSize = true, Left = 12, Top = 12 };
            var nud = new NumericUpDown
            {
                Left = 12,
                Top = 40,
                Width = 160,
                Minimum = -999999,
                Maximum = 999999,
                Value = defaultValue
            };

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Left = 312, Width = 80, Top = 100 };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Left = 412, Width = 80, Top = 100 };

            f.AcceptButton = ok;
            f.CancelButton = cancel;

            f.Controls.AddRange(new Control[] { lbl, nud, ok, cancel });

            return f.ShowDialog() == DialogResult.OK ? (int)nud.Value : null;
        }

        private bool EditThreadConfigDialog(string threadKey, ThreadConfig cfg)
        {
            using var f = new Form
            {
                Text = $"Thread Rule — {threadKey}",
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MinimizeBox = false,
                MaximizeBox = false,
                Width = 620,
                Height = 360
            };

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 6,
                Padding = new Padding(12),
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var priLbl = new Label { Text = "Priority:", AutoSize = true, Anchor = AnchorStyles.Left };
            var priCombo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 260,
                Anchor = AnchorStyles.Left
            };

            var priorities = ConfigLoader.PriorityMap
                .Where(kv => kv.Key is 15 or 2 or 1 or 0 or -1 or -2 or -15)
                .OrderByDescending(kv => kv.Key)
                .Select(kv => new PriorityChoice(kv.Key, kv.Value))
                .ToList();

            if (priorities.Count == 0)
            {
                priorities.AddRange(new[]
                {
                    new PriorityChoice(15, "TIME_CRITICAL"),
                    new PriorityChoice(2, "HIGHEST"),
                    new PriorityChoice(1, "ABOVE_NORMAL"),
                    new PriorityChoice(0, "NORMAL"),
                    new PriorityChoice(-1, "BELOW_NORMAL"),
                    new PriorityChoice(-2, "LOWEST"),
                    new PriorityChoice(-15, "IDLE"),
                });
            }

            priCombo.Items.AddRange(priorities.Cast<object>().ToArray());
            var current = priorities.FirstOrDefault(p => p.Value == cfg.Priority) ?? priorities.FirstOrDefault(p => p.Value == 0);
            if (current != null) priCombo.SelectedItem = current;

            var affLbl = new Label { Text = "Affinity:", AutoSize = true, Anchor = AnchorStyles.Left };
            var aff = new TextBox
            {
                Text = (cfg.Affinity ?? "ALL").Trim(),
                Width = 260,
                Anchor = AnchorStyles.Left | AnchorStyles.Right
            };

            var boost = new CheckBox
            {
                Text = "Disable Priority Boost",
                Checked = cfg.DisableBoost,
                AutoSize = true,
                Anchor = AnchorStyles.Left
            };

            var buttonRow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                WrapContents = false
            };

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 90, Height = ButtonHeight };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90, Height = ButtonHeight };

            buttonRow.Controls.Add(ok);
            buttonRow.Controls.Add(cancel);

            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            layout.Controls.Add(priLbl, 0, 0);
            layout.Controls.Add(priCombo, 1, 0);

            layout.Controls.Add(affLbl, 0, 1);
            layout.Controls.Add(aff, 1, 1);

            layout.Controls.Add(boost, 1, 2);
            layout.Controls.Add(buttonRow, 1, 5);

            f.AcceptButton = ok;
            f.CancelButton = cancel;
            f.Controls.Add(layout);

            if (f.ShowDialog(this) != DialogResult.OK)
                return false;

            if (priCombo.SelectedItem is PriorityChoice pc)
                cfg.Priority = pc.Value;
            else
                cfg.Priority = 0;

            cfg.Affinity = (aff.Text ?? "ALL").Trim();
            cfg.DisableBoost = boost.Checked;
            return true;
        }

        private BigInteger ComputeTopologyBasedHtMask(string choice, string targetClass)
        {

            bool wantHtOff = string.Equals(choice, "HT OFF", StringComparison.OrdinalIgnoreCase);

            CpuTopologyNative.CpuTopology topo;
            try
            {
                topo = CpuTopologyNative.GetTopology();
            }
            catch
            {
                int cpuCount = Math.Max(1, Environment.ProcessorCount);
                if (!wantHtOff)
                {
                    BigInteger all = BigInteger.Zero;
                    for (int i = 0; i < cpuCount; i++)
                        all |= (BigInteger.One << i);
                    return all;
                }
                else
                {
                    BigInteger even = BigInteger.Zero;
                    for (int i = 0; i < cpuCount; i += 2)
                        even |= (BigInteger.One << i);
                    if (even.IsZero) even = BigInteger.One;
                    return even;
                }
            }

            var cls = (targetClass ?? "ALL").Trim().ToUpperInvariant();
            CpuTopologyNative.CoreType restrictTo = CpuTopologyNative.CoreType.Unknown;

            if (cls == "P-CORE")
                restrictTo = CpuTopologyNative.CoreType.PCore;
            else if (cls == "E-CORE")
                restrictTo = CpuTopologyNative.CoreType.ECore;
            else
                restrictTo = CpuTopologyNative.CoreType.Unknown;

            CpuTopologyNative.GroupedAffinityMask grouped;
            if (wantHtOff)
                grouped = CpuTopologyNative.ComputeHtOffMask(topo, restrictTo);
            else
                grouped = CpuTopologyNative.ComputeHtOnMask(topo, restrictTo);

            return grouped.FlatMask;
        }

        private int ResolveRunningPidFromProcessName()
        {
            try
            {
                var baseName = _processName;
                if (baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    baseName = baseName.Substring(0, baseName.Length - 4);

                if (string.IsNullOrWhiteSpace(baseName))
                    return 0;

                var p = Process.GetProcessesByName(baseName).FirstOrDefault();
                if (p == null) return 0;

                try { return p.Id; }
                catch { return 0; }
            }
            catch
            {
                return 0;
            }
        }



        private static string ToHex(BigInteger mask)
        {
            if (mask.Sign < 0)
                mask = BigInteger.Zero;

            if (mask.IsZero)
                return "0x0";

            byte[] bytes = mask.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length == 0)
                return "0x0";

            int start = 0;
            while (start < bytes.Length && bytes[start] == 0) start++;
            if (start >= bytes.Length) return "0x0";

            bytes = bytes.Skip(start).ToArray();

            string hex = BitConverter.ToString(bytes).Replace("-", "");
            hex = hex.TrimStart('0');
            if (hex.Length == 0) hex = "0";

            return "0x" + hex.ToUpperInvariant();
        }

        private sealed class PriorityChoice
        {
            public int Value { get; }
            public string Name { get; }

            public PriorityChoice(int value, string name)
            {
                Value = value;
                Name = name;
            }

            public override string ToString() => $"{Value} ({Name})";
        }
    }
}
