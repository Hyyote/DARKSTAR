using System;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Windows.Forms;

namespace DARKSTAR.UI.WinForms
{
    public sealed class CpuAffinityPickerForm : Form
    {
        private readonly int _cpuCount;

        private TableLayoutPanel _root = null!;
        private FlowLayoutPanel _topButtons = null!;
        private FlowLayoutPanel _bottomButtons = null!;
        private TableLayoutPanel _grid = null!;
        private TextBox _maskTextBox = null!;
        private Label _hintLabel = null!;

        public string SelectedHexMask { get; private set; } = "0x0";

        public CpuAffinityPickerForm(int cpuCount = 0, string? initialMaskHex = null)
        {
            _cpuCount = cpuCount > 0 ? cpuCount : Environment.ProcessorCount;
            if (_cpuCount < 1) _cpuCount = 1;

            InitializeComponent();

            if (!string.IsNullOrWhiteSpace(initialMaskHex))
            {
                if (TryParseHexMask(initialMaskHex.Trim(), out var mask))
                {
                    SetMask(mask);
                }
            }

            UpdateMaskTextFromSelection();
        }

        private void InitializeComponent()
        {
            Text = "CPU Affinity Picker";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            MaximizeBox = true;
            MinimumSize = new Size(520, 420);
            Size = new Size(760, 560);

            const int pad = 10;
            const int buttonH = 34;

            _root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(pad),
                ColumnCount = 1,
                RowCount = 5
            };
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _topButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = true
            };

            var btnAll = MakeButton("All", buttonH, (_, __) => { SelectAll(true); UpdateMaskTextFromSelection(); });
            var btnNone = MakeButton("None", buttonH, (_, __) => { SelectAll(false); UpdateMaskTextFromSelection(); });
            var btnEven = MakeButton("Even", buttonH, (_, __) => { SelectEvenOdd(even: true); UpdateMaskTextFromSelection(); });
            var btnOdd = MakeButton("Odd", buttonH, (_, __) => { SelectEvenOdd(even: false); UpdateMaskTextFromSelection(); });
            var btnInvert = MakeButton("Invert", buttonH, (_, __) => { InvertSelection(); UpdateMaskTextFromSelection(); });

            _topButtons.Controls.AddRange(new Control[] { btnAll, btnNone, btnEven, btnOdd, btnInvert });

            _hintLabel = new Label
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ForeColor = Color.DimGray,
                Text = "Tip: MANUAL affinity uses a CPU bitmask. CPU0 is the least significant bit."
            };

            _grid = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                ColumnCount = 1,
                RowCount = 1
            };

            BuildCpuCheckboxGrid();

            _maskTextBox = new TextBox
            {
                Dock = DockStyle.Top,
                ReadOnly = true,
                Font = new Font(FontFamily.GenericMonospace, 10f),
            };

            _bottomButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                WrapContents = false,
                Padding = new Padding(0, pad, 0, 0)
            };

            var btnOk = MakeButton("OK", buttonH, (_, __) => { SaveAndCloseOk(); });
            var btnCancel = MakeButton("Cancel", buttonH, (_, __) => { DialogResult = DialogResult.Cancel; Close(); });

            AcceptButton = btnOk;
            CancelButton = btnCancel;

            _bottomButtons.Controls.Add(btnOk);
            _bottomButtons.Controls.Add(btnCancel);

            _root.Controls.Add(_topButtons, 0, 0);
            _root.Controls.Add(_hintLabel, 0, 1);
            _root.Controls.Add(_grid, 0, 2);
            _root.Controls.Add(_maskTextBox, 0, 3);
            _root.Controls.Add(_bottomButtons, 0, 4);

            Controls.Add(_root);
        }

        private static Button MakeButton(string text, int height, EventHandler onClick)
        {
            var b = new Button
            {
                Text = text,
                Height = height,
                AutoSize = true,
                Padding = new Padding(14, 6, 14, 6),
                Margin = new Padding(0, 0, 8, 0)
            };
            b.Click += onClick;
            return b;
        }

        private void BuildCpuCheckboxGrid()
        {
            int cols = _cpuCount switch
            {
                <= 8 => 4,
                <= 16 => 6,
                <= 32 => 8,
                <= 64 => 10,
                _ => 12
            };

            var grid = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                ColumnCount = cols,
                RowCount = (int)Math.Ceiling(_cpuCount / (double)cols),
                Padding = new Padding(0),
                Margin = new Padding(0),
            };

            for (int c = 0; c < cols; c++)
                grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            for (int r = 0; r < grid.RowCount; r++)
                grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            for (int i = 0; i < _cpuCount; i++)
            {
                var cb = new CheckBox
                {
                    Text = $"CPU {i}",
                    AutoSize = true,
                    Margin = new Padding(6, 4, 12, 4),
                    Tag = i
                };
                cb.CheckedChanged += (_, __) => UpdateMaskTextFromSelection();

                int row = i / cols;
                int col = i % cols;
                grid.Controls.Add(cb, col, row);
            }

            _grid.Controls.Clear();
            _grid.Controls.Add(grid);
        }

        private void SelectAll(bool on)
        {
            foreach (var cb in GetCpuCheckboxes())
                cb.Checked = on;
        }

        private void SelectEvenOdd(bool even)
        {
            foreach (var cb in GetCpuCheckboxes())
            {
                int idx = (int)cb.Tag!;
                cb.Checked = even ? (idx % 2 == 0) : (idx % 2 == 1);
            }
        }

        private void InvertSelection()
        {
            foreach (var cb in GetCpuCheckboxes())
                cb.Checked = !cb.Checked;
        }

        private CheckBox[] GetCpuCheckboxes()
        {
            if (_grid.Controls.Count == 0) return Array.Empty<CheckBox>();
            var inner = _grid.Controls[0];
            return inner.Controls.OfType<CheckBox>().ToArray();
        }

        private BigInteger GetMaskFromSelection()
        {
            BigInteger mask = BigInteger.Zero;
            foreach (var cb in GetCpuCheckboxes())
            {
                if (!cb.Checked) continue;
                int idx = (int)cb.Tag!;
                mask |= (BigInteger.One << idx);
            }
            return mask;
        }

        private void SetMask(BigInteger mask)
        {
            foreach (var cb in GetCpuCheckboxes())
            {
                int idx = (int)cb.Tag!;
                bool on = (mask & (BigInteger.One << idx)) != BigInteger.Zero;
                cb.Checked = on;
            }
        }

        private void UpdateMaskTextFromSelection()
        {
            var mask = GetMaskFromSelection();
            _maskTextBox.Text = ToHex(mask);
        }

        private void SaveAndCloseOk()
        {
            var mask = GetMaskFromSelection();
            SelectedHexMask = ToHex(mask);
            DialogResult = DialogResult.OK;
            Close();
        }

        private static bool TryParseHexMask(string text, out BigInteger mask)
        {
            mask = BigInteger.Zero;

            if (string.IsNullOrWhiteSpace(text))
                return false;

            text = text.Trim();

            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(2);

            text = new string(text.Where(c => !char.IsWhiteSpace(c) && c != '_').ToArray());

            if (text.Length == 0)
            {
                mask = BigInteger.Zero;
                return true;
            }

            try
            {
                mask = BigInteger.Parse("0" + text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
                return true;
            }
            catch
            {
                return false;
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
    }
}
