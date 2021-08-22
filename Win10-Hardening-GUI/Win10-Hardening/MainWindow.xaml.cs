using Win10Hardening.Views;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.WindowsAPICodePack.Dialogs;
using System.Diagnostics;
using Win10Hardening.Util;

namespace Win10Hardening
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Apps AppsPage = new Apps();
        private Services ServicesPage = new Services();
        private Misc MiscPage = new Misc();
        private EdgeAndIE EdgeIEPage = new EdgeAndIE();
        private Office OfficePage = new Office();
        private Net NetPage = new Net();

        public MainWindow()
        {
            InitializeComponent();
            
            // ensure the application is running with local administrator privileges
            bool isAdmin = Utilities.IsAdministrator();
            if (! isAdmin)
            {
                MessageBox.Show("This application must run with Administrator privileges", "", MessageBoxButton.OK, MessageBoxImage.Error);
                Application.Current.Shutdown();
            }

            // Center the window and modify its size
            Title = "Win10-Hardening";
            Width = 550;
            Height = 430;
            ResizeMode = ResizeMode.NoResize;
            Left = (SystemParameters.PrimaryScreenWidth / 2) - (Width / 2);
            Top = (SystemParameters.PrimaryScreenHeight / 2) - (Height / 2);


            // Define and add a TabItem for each Page
            TabItem ti = new TabItem();
            Frame tabFrame = new Frame();
            ti.Header = "Office";
            tabFrame.Content = OfficePage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            
            ti = new TabItem();
            tabFrame = new Frame();
            ti.Header = "Edge/IE";
            tabFrame.Content = EdgeIEPage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            
            ti = new TabItem();
            tabFrame = new Frame();
            ti.Header = "Network";
            tabFrame.Content = NetPage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            
            ti = new TabItem();
            ti.Header = "Apps";
            tabFrame = new Frame();
            tabFrame.Content = AppsPage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            
            ti = new TabItem();
            tabFrame = new Frame();
            ti.Header = "Services";
            tabFrame.Content = ServicesPage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            
            ti = new TabItem();
            tabFrame = new Frame();
            ti.Header = "Misc";
            tabFrame.Content = MiscPage;
            ti.Content = tabFrame;
            tabControl.Items.Add(ti);
            

            // Add select/unselect events handlers
            sel_evrthng.Click += new RoutedEventHandler(AppsPage.SelectAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(ServicesPage.SelectAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(EdgeIEPage.SelAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(EdgeIEPage.SelAllChckBox2);
            sel_evrthng.Click += new RoutedEventHandler(MiscPage.SelectAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(MiscPage.SelWinDef);
            sel_evrthng.Click += new RoutedEventHandler(OfficePage.SelectAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(NetPage.SelectAllChkBox);
            sel_evrthng.Click += new RoutedEventHandler(NetPage.HardenSMBserver);
            sel_evrthng.Click += new RoutedEventHandler(NetPage.HardenRDPserver);
            unsel_evrthng.Click += new RoutedEventHandler(AppsPage.UnselectAllChkBox);
            unsel_evrthng.Click += new RoutedEventHandler(ServicesPage.UnselectAllChkBox);
            unsel_evrthng.Click += new RoutedEventHandler(EdgeIEPage.UnselAllChckBox);
            unsel_evrthng.Click += new RoutedEventHandler(EdgeIEPage.UnselAllChckBox2);
            unsel_evrthng.Click += new RoutedEventHandler(MiscPage.UnselWinDef);
            unsel_evrthng.Click += new RoutedEventHandler(MiscPage.UnselectAllChkBox);
            unsel_evrthng.Click += new RoutedEventHandler(OfficePage.UnselectAllChkBox);
            unsel_evrthng.Click += new RoutedEventHandler(NetPage.UnselectAllChkBox);
        }

        private void HardenBtn_Click(object sender, RoutedEventArgs e)
        {
            List<string> apps_selected = AppsPage.GetSelected(),
                         services_selected = ServicesPage.GetSelected(),
                         office_selected = OfficePage.GetSelected(),
                         edge_selected = EdgeIEPage.GetSelectedEdgeOpt(),
                         ie_selected = EdgeIEPage.GetSelectedIEopt(),
                         netword_selected = NetPage.GetSelected(),
                         misc_selected = MiscPage.GetSelected();

            List<string>[] pages = new List<String>[] { apps_selected, services_selected, office_selected, edge_selected, ie_selected, netword_selected, misc_selected };
            // If no CheckBox isChecked, then display an error message and then quit the app.
            if (new[] { apps_selected.Count, services_selected.Count, office_selected.Count, edge_selected.Count, ie_selected.Count, netword_selected.Count, misc_selected.Count }.All(x => x == 0))
            {
                MessageBox.Show("No checkbox was checked.\nPlease select at least one option.", "", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string chsnPages = "";
            foreach (var p in pages)
            {
                if (p.Count != 0)
                {
                    int i = pages.ToList().IndexOf(p);
                    if (i == 0)
                        chsnPages += "- Apps\n";
                    else if (i == 1)
                        chsnPages += "- Services\n";
                    else if (i == 2)
                        chsnPages += "- Office\n";
                    else if (i == 3)
                        chsnPages += "- Edge section\n";
                    else if (i == 4)
                        chsnPages += "- IE section\n";
                    else if (i == 5)
                        chsnPages += "- Net\n";
                    else if (i == 6)
                        chsnPages += "- Misc\n";
                }
            }

            if (MessageBox.Show("You modified the following pages:\n" + chsnPages + "\nStart the hardening procedure?\n", "Question", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.No)
                MessageBox.Show("Procedure Aborted", "", MessageBoxButton.OK, MessageBoxImage.Information);
            else
            {
                MessageBox.Show("Select a folder to store registry backup files", "", MessageBoxButton.OK, MessageBoxImage.Information);

                List<String> res_apps = AppsPage.GetSelected();
                List<String> res_services = ServicesPage.GetSelected();

                var dlg = new CommonOpenFileDialog();
                string currentDirectory = "";
                dlg.Title = "My Title";
                dlg.IsFolderPicker = true;
                dlg.InitialDirectory = currentDirectory;
                dlg.AddToMostRecentlyUsedList = false;
                dlg.AllowNonFileSystemItems = false;
                dlg.DefaultDirectory = currentDirectory;
                dlg.EnsureFileExists = true;
                dlg.EnsurePathExists = true;
                dlg.EnsureReadOnly = false;
                dlg.EnsureValidNames = true;
                dlg.Multiselect = false;
                dlg.ShowPlacesList = true;

                var folder = "";
                if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    folder = dlg.FileName;
                }
                else
                {
                    MessageBox.Show("You must choose one directory to store the backup files.", "", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                IsEnabled = false;
                MessageBox.Show("Perfoming the backup..\nPlease wait..", "", MessageBoxButton.OK, MessageBoxImage.Information);
                Task registryBackupTask = Task.Factory.StartNew(() => Utilities.PerformRegistryBackup(folder));
                Task.WaitAll(registryBackupTask);

                MessageBox.Show("Backup successfully created", "", MessageBoxButton.OK, MessageBoxImage.Information);
                IsEnabled = true;

                Utilities.UninstallApps(apps_selected);                                 // Uninstall selected Apps
                Utilities.DisableServices(services_selected);                           // Disable selectes Services
                Utilities.HardenOffice(office_selected);                                          // Office Tweaks
                Utilities.HardenIE(ie_selected);                                                  // IE Tweaks
                Utilities.HardenEdge(edge_selected);                                              // Edge Tweaks
                Utilities.HardenNet(netword_selected);                                            // Network Tweaks
                Utilities.HardenMisc(misc_selected, MiscPage.GetUACSelectedLevel());         // Misc Tweaks

                if (MessageBox.Show("The procedure completed successfully.\nRestart your computer now to apply all the changes?", "Question", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                    Process.Start("shutdown", "/r /t 0"); 
            }
        }
    }
}
