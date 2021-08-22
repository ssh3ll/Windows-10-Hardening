using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Win10Hardening.Util;
using Win10Hardening.Views.Interfaces;

namespace Win10Hardening.Views
{
    /// <summary>
    /// Interaction logic for Misc.xaml
    /// </summary>
    public partial class Misc : Page, SelectInterface
    {
        public Misc()
        {
            InitializeComponent();
            LoadMiscPage();
        }

        private void LoadMiscPage()
        {
            string[] miscTweaksStrings = new string[] { "Disable AutoPlay & AutoRun", "Disable WiFi Sense", "Disable Telemetry", "Enable SmartScreen", "Disable WebSearch", "Disable Background Apps", "Disable Feedback", "Disable Advertising ID", "Disable Sticky Keys", "Disable Find MyDevice", "Disable Win Insider Program", "Disable Active Desktop", "Disable Picture Password", "Enhance Face Spoofing Protection" };
            string[] winDefStrings = new string[] { "Enable Real-Time Monitoring", "Disable Automatic Sample Submission", "Check Signatures before any Scan" };

            CheckBox selectAll = Utilities.BuildSelectChkBox(UConstants.SelectAllStr, "Select All", UConstants.cmmnThickness, false, 180);
            CheckBox deselectAll = Utilities.BuildSelectChkBox(UConstants.UnselectAllStr, "Unselect All", UConstants.cmmnThickness, false, 180);
            selectAll.Checked += new RoutedEventHandler(SelectAllChkBox);
            deselectAll.Checked += new RoutedEventHandler(UnselectAllChkBox);
            wrapPane.Children.Add(selectAll);
            wrapPane.Children.Add(deselectAll);


            int i = 0;
            foreach (string s in miscTweaksStrings)
            {
                i++;
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", s, UConstants.topThick, (s.Contains("SmartScreen")) ? true : false, 200);
                wrapPane.Children.Add(chkBox);
            }

            Label passPolicyLabel = new Label
            {
                Name = "passPolicyLabel",
                Content = "UAC",
                Width = 240,
                Height = 30,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                FontWeight = FontWeights.Bold
            };
            uacPanel.Children.Add(passPolicyLabel);


            ComboBox comboBox = new ComboBox();
            comboBox.Name = "uacComboBox";
            comboBox.Width = 100;
            comboBox.HorizontalAlignment = HorizontalAlignment.Left;
            comboBox.Margin = new Thickness(0, 0, 15, 0);
            comboBox.Items.Add("Low");
            comboBox.Items.Add("Medium");
            comboBox.Items.Add("High");
            comboBox.SelectedIndex = 2;

            uacPanel.Children.Add(comboBox);
            

            Label windefLabel = new Label
            {
                Name = "windefLabel",
                Content = "Windows Defender",
                Width = 240,
                Height = 30,
                Visibility = Visibility.Visible,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                FontWeight = FontWeights.Bold
            };
            windefPanel.Children.Add(windefLabel);


            i = 0;
            foreach (string s in winDefStrings)
            {
                i++;
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", s, i == winDefStrings.Length ? UConstants.topRghtThick : UConstants.topThick, true);
                windefPanel.Children.Add(chkBox);
            }
        }



        public void SelectAllChkBox(object sender, RoutedEventArgs e)
        {
            List<CheckBox> l = p2.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.UnselectAllStr).ToList();
            if (l.Count != 0)
                l.First().IsChecked = false;
            wrapPane.Children.OfType<CheckBox>().Where(cb => cb.Name != UConstants.UnselectAllStr && cb.Name != UConstants.SelectAllStr).ToList().ForEach(cb => cb.IsChecked = true);
            wrapPane.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.UnselectAllStr).ToList().ForEach(cb => cb.IsChecked = false);
        }

        public void UnselectAllChkBox(object sender, RoutedEventArgs e)
        {
            List<CheckBox> l = p2.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.SelectAllStr).ToList();                // unchecks "Select All"
            if(l.Count != 0)
                l.First().IsChecked = false;
            wrapPane.Children.OfType<CheckBox>().Where(cb => cb.Name != UConstants.UnselectAllStr).ToList().ForEach(cb => cb.IsChecked = false);
        }

        public List<string> GetSelected()
        {
            var res = new List<string>();
            IEnumerable<CheckBox> chkBoxes = windefPanel.Children.OfType<CheckBox>().Concat(wrapPane.Children.OfType<CheckBox>());
            foreach (CheckBox cb in chkBoxes)
                if (cb.IsChecked == true && cb.Name != UConstants.UnselectAllStr && cb.Name != UConstants.SelectAllStr)
                    res.Add(cb.Content.ToString());
            
            return res;
        }

        public string GetUACSelectedLevel()
        {
            // Returns the selected UAC value
            return uacPanel.Children.OfType<ComboBox>().First().Text;
        }

        public void UnselWinDef(object sender, RoutedEventArgs e)
        {
            windefPanel.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);
        }

        public void SelWinDef(object sender, RoutedEventArgs e)
        {
            windefPanel.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);
        }
    }
}
