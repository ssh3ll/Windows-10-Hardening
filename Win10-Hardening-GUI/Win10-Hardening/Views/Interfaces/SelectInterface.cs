using System.Collections.Generic;
using System.Windows;

namespace Win10Hardening.Views.Interfaces
{
    interface SelectInterface
    {
        void SelectAllChkBox(object sender, RoutedEventArgs e);
        void UnselectAllChkBox(object sender, RoutedEventArgs e);
        List<string> GetSelected();
    }
}
