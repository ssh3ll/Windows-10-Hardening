using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Win10Hardening.Util;
using Win10Hardening.Views.Interfaces;

namespace Win10Hardening.Views
{
    /// <summary>
    /// Interaction logic for Services.xaml
    /// </summary>
    public partial class Services : Page, SelectInterface
    {
        public static List<string> ServiceNames;
        
        public Services()
        {
            InitializeComponent();
            LoadServicesPage();
        }

        private void LoadServicesPage()
        {
            ServiceNames = Utilities.GetRunningServices();                 // Load Service names from running system

            // Define select/unselect all buttons and their events handlers
            CheckBox SelectAll = Utilities.BuildSelectChkBox(UConstants.SelectAllStr, $"Select All ({ServiceNames.Count})", UConstants.cmmnThickness);
            CheckBox DeselectAll = Utilities.BuildSelectChkBox(UConstants.UnselectAllStr, "Unselect All", UConstants.cmmnThickness);
            SelectAll.Checked += new RoutedEventHandler(SelectAllChkBox);
            DeselectAll.Checked += new RoutedEventHandler(UnselectAllChkBox);
            p2.Children.Add(SelectAll);
            p2.Children.Add(DeselectAll);


            int i = 0;
            foreach (string serviceNameStr in ServiceNames)
            {
                i += 1;
                string boxName = $"checkBox{i}";
                CheckBox checkBox = Utilities.ChckBox(boxName, serviceNameStr, i == 1 ? UConstants.frstThickness : UConstants.thick);

                p1.Children.Add(checkBox);
            }
        }

        public void SelectAllChkBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;               // unchecks "Unselect All"
            p1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);                                                         // checks each other CheckBox
        }

        public void UnselectAllChkBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name != UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;               // unchecks "Select All"
            p1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);                                                        // checks each other CheckBox
        }

        public List<string> GetSelected()
        {
            var res = new List<string>();
            foreach (CheckBox chkBox in p1.Children.OfType<CheckBox>())
                if (chkBox.IsChecked == true)
                    res.Add(chkBox.Content.ToString());

            return res;
        }
    }
}