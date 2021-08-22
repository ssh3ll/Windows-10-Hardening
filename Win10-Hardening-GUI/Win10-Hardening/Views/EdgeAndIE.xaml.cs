using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Win10Hardening.Util;

namespace Win10Hardening.Views
{
    /// <summary>
    /// Interaction logic for EdgeAndIE.xaml
    /// </summary>
    public partial class EdgeAndIE : Page
    {
        public EdgeAndIE()
        {
            InitializeComponent();
            LoadEdgePage();
        }

        private void LoadEdgePage()
        {
            var strings_IE = new string[] { "Disable Location", "Enable Phishing Filter", "Disable inPrivate logging", "Disable CEIP", "Disable Suggestions", "Disable Continuous Browsing", "Disable Prefetching", "Always send DNT Header", "Disable Crash Detection", "Clear History on Exit", "Force HTTP/2", "Disable SSLv3 Fallback" };
            var string_edge = new string[] { "Disable Flash Player", "Always send the DNT Header", "Disable Third-party Cookies", "Prevent Data Collection", "Enable Phishing Filter", "Disable Help Prompt", "Clear History on Exit", "Disable Suggestions" };

            CheckBox SelectAll = Utilities.BuildSelectChkBox(UConstants.SelectAllStr, "Select All", UConstants.cmmnThickness);
            CheckBox DeselectAll = Utilities.BuildSelectChkBox(UConstants.UnselectAllStr, "Unselect All", UConstants.cmmnThickness);
            SelectAll.Checked += new RoutedEventHandler(SelAllChkBox);
            DeselectAll.Checked += new RoutedEventHandler(UnselAllChckBox);
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
            foreach (string ieOptStr in strings_IE)
            {
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", ieOptStr, UConstants.rghtThick, false, 180);
                wrapPane1.Children.Add(chkBox);
            }
            
            Label blankLabel = new Label{Name = "edgeLabel", Content = "                                                                                                                ", FontWeight = FontWeights.Bold,};
            Label l = new Label{Name = "edgeLabel", Content = "Microsoft Edge Tweaks", FontWeight = FontWeights.Bold,};
            Label l2 = new Label{Name = "edgeLabel", Content = "                                             ", FontWeight = FontWeights.Bold,};
            Label l3 = new Label{Name = "edgeLabel", Content = "                                             ", FontWeight = FontWeights.Bold,};

            wrapPane2.Children.Add(blankLabel);
            wrapPane2.Children.Add(l);
            wrapPane2.Children.Add(l2);
            wrapPane2.Children.Add(l3);


            CheckBox sALL = Utilities.BuildSelectChkBox($"{UConstants.SelectAllStr}2", "Select All", UConstants.cmmnThickness);
            CheckBox dALL = Utilities.BuildSelectChkBox($"{UConstants.UnselectAllStr}2", "Unselect All", UConstants.cmmnThickness);
            sALL.Checked += new RoutedEventHandler(SelAllChckBox2);
            dALL.Checked += new RoutedEventHandler(UnselAllChckBox2);
            wrapPane2.Children.Add(sALL);
            wrapPane2.Children.Add(dALL);

            Label l4 = new Label{Name = "edgeLabel", Content = "                                             ", FontWeight = FontWeights.Bold,};
            wrapPane2.Children.Add(l4);

            foreach (string edgeOptStr in string_edge)
            {
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", edgeOptStr, UConstants.rghtThick, false, 180);
                wrapPane2.Children.Add(chkBox);
            }
        }


        public void SelAllChkBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name == UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;                       // unchecks "Unselect All"
            wrapPane1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);                                                          // checks each other CheckBox
        }

        public void UnselAllChckBox(object sender, RoutedEventArgs e)
        {
            p2.Children.OfType<CheckBox>().Where(cb => cb.Name != UConstants.UnselectAllStr).First<CheckBox>().IsChecked = false;                           // unchecks "Select All"
            wrapPane1.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);      // checks each other CheckBox
        }

        public void SelAllChckBox2(object sender, RoutedEventArgs e)
        {
            wrapPane2.Children.OfType<CheckBox>().Where(cb => cb.Name == $"{UConstants.UnselectAllStr}2").First<CheckBox>().IsChecked = false;              // unchecks "Unselect All"
            wrapPane2.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);                                                              // checks each other CheckBox
        }

        public void UnselAllChckBox2(object sender, RoutedEventArgs e)
        {
            wrapPane2.Children.OfType<CheckBox>().Where(cb => cb.Name != $"{UConstants.UnselectAllStr}2").First<CheckBox>().IsChecked = false;              // unchecks "Select All"
            wrapPane2.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);      // checks each other CheckBox
        }

        public List<string> GetSelectedIEopt()
        {
            var res = new List<string>();
            List<CheckBox> l = wrapPane1.Children.OfType<CheckBox>().Where(cb => cb.Name != $"{UConstants.UnselectAllStr}2" && cb.Name != $"{UConstants.SelectAllStr}2" && cb.IsChecked == true).ToList();
            foreach (CheckBox cb in l)
                res.Add(cb.Content.ToString());

            return res;
        }

        public List<string> GetSelectedEdgeOpt()
        {
            var res = new List<string>();
            List<CheckBox> l = wrapPane2.Children.OfType<CheckBox>().Where(cb => cb.Name != $"{UConstants.UnselectAllStr}2" && cb.Name != $"{UConstants.SelectAllStr}2" && cb.IsChecked == true).ToList();
            foreach (CheckBox cb in l)
                res.Add(cb.Content.ToString());

            return res;
        }
    }
}
