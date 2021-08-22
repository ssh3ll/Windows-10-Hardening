using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Win10Hardening.Util;

namespace Win10Hardening.Views
{
    /// <summary>
    /// Interaction logic for Office.xaml
    /// </summary>
    public partial class Office : Page
    {
        public Office()
        {
            InitializeComponent();
            LoadOfficePage();
        }

        private void LoadOfficePage()
        {
            var optNames = new string[] {"Disable Macros", "Disable DDE", "Enable Automatic Updates", "Disable Feedback", "Disable Data Collection & Telemetry", "Deny Internet for Office", "Disable Online Repair" };

            CheckBox SelectAll = Utilities.BuildSelectChkBox(UConstants.SelectAllStr, "Select All", UConstants.cmmnThickness);
            CheckBox DeselectAll = Utilities.BuildSelectChkBox(UConstants.UnselectAllStr, "Unselect All", UConstants.cmmnThickness);
            SelectAll.Checked += new RoutedEventHandler(SelectAllChkBox);
            DeselectAll.Checked += new RoutedEventHandler(UnselectAllChkBox);
            p2.Children.Add(SelectAll);
            p2.Children.Add(DeselectAll);

            Label label = new Label
            {
                Name = "blank",
                Content = "   ",
                Width = 240,
                Height = 30,
                Visibility = Visibility.Visible,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top
            };
            p2.Children.Add(label);

            int i = 0;
            foreach (string optStr in optNames)
            {
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", optStr, UConstants.rghtThick, (optStr.Contains("DDE") || optStr.Contains("Macros") || optStr.Contains("Automatic Updates")) ? true : false, 215);
                wrapPane1.Children.Add(chkBox);
            }
        }

        public void SelectAllChkBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;                       // unchecks "Unselect All"
            wrapPane1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);                                                          // checks each other CheckBox
        }

        public void UnselectAllChkBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name != UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;               // unchecks "Select All"
            wrapPane1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);                                                 // checks each other CheckBox
        }

        public List<string> GetSelected()
        {
            var res = new List<string>();
            foreach (CheckBox chkBox in wrapPane1.Children.OfType<CheckBox>())
                if (chkBox.IsChecked == true)
                    res.Add(chkBox.Content.ToString());

            return res;
        }
    }
}
