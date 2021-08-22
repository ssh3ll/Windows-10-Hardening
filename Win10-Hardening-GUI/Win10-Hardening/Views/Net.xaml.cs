using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Win10Hardening.Util;
using Win10Hardening.Views.Interfaces;

namespace Win10Hardening.Views
{
    /// <summary>
    /// Interaction logic for Net.xaml
    /// </summary>
    public partial class Net : Page, SelectInterface
    {
        public Net()
        {
            InitializeComponent();
            LoadNetPage();
        }

        private void LoadNetPage()
        {
            string[] general_strings = new string[]{"Flush Caches", "Disable Unneeded Net Interfaces", "Disable Unsafe Net Protocols", "Disable IPv6" };
            string[] smb_strings = new string[] {"Disable SMB Server", "Disable Sharing Mapped Drives", "Disable Admin Shares", "Disable NetBios", "Disable LLMNR" };
            string[] rdp_strings = new string[] {"Disable Remote Assistance", "Mandatory Encrypted Tickets", "Disable Remote Desktop Sharing", "Disable Password Saving", "Do not allow Remote Shell" };

            var th1 = new Thickness(0, 7, 15, 0);
            var th2 = new Thickness(0, 7, 15, 10);

            int i = 0;
            foreach (string generalOptStr in general_strings)
            {
                i++;
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", generalOptStr, i == general_strings.Length ? th2 : th1, true);
                generalPane.Children.Add(chkBox);
            }
            
            Label label = new Label{Name = "smbLabel", Content = "SMB & Shares:", Width = 240, Height = 30, Visibility = Visibility.Visible, HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, FontWeight = FontWeights.Bold};
            smbStackPanel.Children.Add(label);

            i = 0;
            foreach (string smbOptStr in smb_strings)
            {
                i++;
                CheckBox chkBox = new CheckBox
                {
                    Name = $"chkBox{i}",
                    IsChecked = false,
                    Content = smbOptStr,
                    Margin = i == smb_strings.Length ? th2 : th1,
                    FontWeight = smbOptStr.Contains("NetBios") || smbOptStr.Contains("LLMNR") ? FontWeights.Bold : FontWeights.Normal
                };
                smbStackPanel.Children.Add(chkBox);
            }

            Label l2 = new Label{Name = "rdpLabel", Content = "RDP:", Width = 240, Height = 30, Visibility = Visibility.Visible, HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, FontWeight = FontWeights.Bold};
            rdpStackPanel.Children.Add(l2);

            CheckBox rdpChkBox = new CheckBox
            {
                Name = "rdpChkBox",
                Content = "Disable RDP",
                Visibility = Visibility.Visible,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                FontWeight = FontWeights.Bold
            };
            rdpStackPanel.Children.Add(rdpChkBox);

            foreach (string rdpOptStr in rdp_strings)
            {
                CheckBox chkBox = Utilities.BuildSelectChkBox($"chkBox{i}", rdpOptStr, th1, false);
                rdpStackPanel.Children.Add(chkBox);
            }
        }


        public List<string> GetSelected()
        {
            var res = new List<string>();
            IEnumerable<CheckBox> chckBoxes = generalPane.Children.OfType<CheckBox>().Concat(smbStackPanel.Children.OfType<CheckBox>()).Concat(rdpStackPanel.Children.OfType<CheckBox>());
            foreach (CheckBox cb in chckBoxes)
                if(cb.IsChecked == true)
                    res.Add(cb.Content.ToString());

            return res;
        }

        public void SelectAllChkBox(object sender, RoutedEventArgs e)
        {
            generalPane.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = true);
        }

        public void UnselectAllChkBox(object sender, RoutedEventArgs e)
        {
            generalPane.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);
            smbStackPanel.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);
            rdpStackPanel.Children.OfType<CheckBox>().ToList().ForEach(cb => cb.IsChecked = false);
        }

        public void HardenSMBserver(object sender, RoutedEventArgs e)
        {
            IEnumerable<CheckBox> res = smbStackPanel.Children.OfType<CheckBox>();
            foreach (CheckBox tmp in res)    
                tmp.IsChecked = true;
        }

        public void HardenRDPserver(object sender, RoutedEventArgs e)
        {
            IEnumerable<CheckBox> res = rdpStackPanel.Children.OfType<CheckBox>();
            foreach (CheckBox tmp in res)
                tmp.IsChecked = true;
        }
    }
}
