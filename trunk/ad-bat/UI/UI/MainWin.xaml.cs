using System;
using System.Globalization;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.Windows.Interop;
namespace AdBAT
{
    /// <summary>
    /// Interaction logic for Window1.xaml
    /// </summary>
    /// 
    public partial class MainWin : Window
    {
        #region Initialize
        public static IntPtr hwnd = IntPtr.Zero;//当前窗口句柄
        public static readonly string FileName = System.Windows.Forms.Application.StartupPath+
            @"\Events\" + DateTime.Now.ToString("yyyyMMddHHmmss", DateTimeFormatInfo.InvariantInfo) 
            + ".xml";
        System.Windows.Forms.NotifyIcon notifyIcon = new System.Windows.Forms.NotifyIcon();

        public MainWin()
        {
            InitializeComponent();
        }
        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            HwndSource hwndSource = PresentationSource.FromVisual(this) as HwndSource;
            if (hwndSource != null)
            {
                hwndSource.AddHook(new HwndSourceHook(this.WndProc));
            }
        }
        protected virtual IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)//消息处理
        {
            switch (msg)
            {
                case 0x501:
                    {
                        List<PID> PIDList = new List<PID>();
                        PIDList = XML_W_R.XMLRead(FileName);
                        PID mypid=new PID();
                        mypid.ID="test id";
                        mypid.myICO=ICO.getICOFP("FetionFx");
                        mypid.Children.Add("child1");
                        mypid.Children.Add("child2");
                        PIDList.Add(mypid);

                        //Raise Warnning Window,write the information to File named "temp.tmp"
                        
                        File.WriteAllText("temp.tmp","test haha");
                        WinRaise();
                        XML_W_R.XMLWrite(PIDList, FileName);
                        SetBindingOfTreeView(FileName);
                        break;
                    }
                case 0x502:
                    {
                        //Handle the Deny option
                        MessageBox.Show("you chose deny");
                        break;
                    }
                case 0x503:
                    {
                        //Handle the Allow option
                        MessageBox.Show("you chose allow");
                        break;
                    }
                case 0x504:
                    {
                        //Handle the Next time option
                        MessageBox.Show("you chose next");
                        break;
                    }

            }
            return IntPtr.Zero;
        }
        #endregion
        public void DragWindow(object sender, MouseButtonEventArgs args)//设置窗体移动
        {
            this.DragMove();
        }
        public void Close_Btn_Click(object sender, RoutedEventArgs args)
        {
            MinToNotify();
        }
        private void Min_Btn_Click(object sender, RoutedEventArgs e)//test NotifyIcon
        {
            this.WindowState = WindowState.Minimized;
        }
        private void ShowNotifyIcon()//设置托盘图标相关信息
        {
            this.notifyIcon.Icon = (System.Drawing.Icon)(AdBAT.Properties.Resources.MainICO);
            this.notifyIcon.BalloonTipText = "AD-BAT";
            this.notifyIcon.Text = "AD-BAT";
            this.notifyIcon.MouseDoubleClick += OnNotifyIconDoubleClick;

            this.notifyIcon.Visible = true;

            //    this.notifyIcon.BalloonTipText = "Hello, NotifyIcon!";
            //    this.notifyIcon.Text = "Hello, NotifyIcon!";
            //    this.notifyIcon.Icon = new System.Drawing.Icon("MainICO.ico");
            //    this.notifyIcon.Visible = true;
            //    notifyIcon.MouseDoubleClick += OnNotifyIconDoubleClick;
            //    this.notifyIcon.ShowBalloonTip(1000);

        }
        private void OnNotifyIconDoubleClick(object sender, EventArgs e)//恢复正常窗口显示
        {
            this.WindowState = WindowState.Normal;
            this.Show();
            this.ShowInTaskbar = true;
            this.notifyIcon.Visible = false;
        }
        private void MinToNotify()//最小化到托盘
        {
            this.Hide();
            this.ShowInTaskbar = false;
            this.WindowState = WindowState.Minimized;
            ShowNotifyIcon();
        }
        private void SaveSetting()//保存设置
        {
            int ProtectType=0;
            int Mode=1;
            if (File_cb.IsChecked==true)
            {
                ProtectType += 1;
            }
            if (Process_cb.IsChecked==true)
            {
                ProtectType += 2;
            }
            if (Register_cb.IsChecked==true)
            {
                ProtectType += 4;
            }
            if (Other_cb.IsChecked==true)
            {
                ProtectType += 8;
            }
            Mode =Convert.ToInt32(Grade_Slider.Value);
            Setting mysetting = new Setting();
            mysetting.Mode = Mode;
            mysetting.ProtectType = ProtectType;
            XML_W_R.WriteSetting(mysetting,"Setting.xml");
            RecoverSetting();
        }
        private void RecoverSetting()//更新设置并设置监控
        {
            Setting mysetting = new Setting();
            mysetting = XML_W_R.ReadSetting("Setting.xml");
            int Mode=mysetting.Mode;
            int ProtectType=mysetting.ProtectType;
            Grade_Slider.Value=Mode;
            //Set Mode
            switch (ProtectType)
            {
                case 0://无防护
                    {
                        
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = false;
                        break;

                    }
                case 1://文件防护
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 2://进程防护
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 4://注册表防护
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 8://其他防护
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 3://文件+进程
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 5://文件+注册表
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 9://文件+其他
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 11://文件+进程+其他
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 7://文件+进程+注册表
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 13://文件+注册表+其他
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 15://文件+进程+注册表+其他
                    {
                        File_cb.IsChecked = true;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 6://进程+注册表
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = false;
                        break;
                    }
                case 10://进程+其他
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = false;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 14://进程+注册表+其他
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = true;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = true;
                        break;
                    }
                case 12://注册表+其他
                    {
                        File_cb.IsChecked = false;
                        Process_cb.IsChecked = false;
                        Register_cb.IsChecked = true;
                        Other_cb.IsChecked = true;
                        break;
                    }


            }
        }
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            hwnd = new WindowInteropHelper(this).Handle;//获取当前窗口句柄
            SetBindingOfTreeView(FileName);
            RecoverSetting();
        }

        private void WinRaise()//弹出警告窗口
        {
            WarnWin childwin = new WarnWin();
            childwin.ShowDialog();
        }


        private void sendmessage(int msg)//发送消息
        {
            Win32 mywin32 = new Win32();
            mywin32.SendMsgToMainForm(hwnd.ToInt32(),msg);
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)//阻止正常关闭
        {
            //e.Cancel = true;
        }

        private void Grade_Slider_ValueChanged(object sender, RoutedEventArgs e)//模式选择
        {
            switch (Convert.ToInt32(Grade_Slider.Value))
            {
                case 1:
                    {
                        Normal_la.Foreground = Brushes.White;
                        Game_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        Pro_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        break;
                    }
                case 2:
                    {
                        Game_la.Foreground = Brushes.White;
                        Normal_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        Pro_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        break;
                    }
                case 3:
                    {
                        Pro_la.Foreground = Brushes.White;
                        Normal_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        Game_la.Foreground = new SolidColorBrush(Color.FromArgb(100, 171, 15, 15));
                        break;
                    }
            }
        }

        private void SetBindingOfTreeView(string strSourceFileUri)//动态设置数据绑定
        {
            XmlDataProvider myXmlDataProvider = new XmlDataProvider();
            myXmlDataProvider.Source = new Uri(strSourceFileUri);
            //myXmlDataProvider.XPath = "Ad-BAT";//必须为根节点
            myXmlDataProvider.XPath = "Ad-BAT";
            Binding newbinding = new Binding();
            newbinding.Mode = BindingMode.OneWay;
            newbinding.Source = myXmlDataProvider;
            //newbinding.XPath = "PIDLIST";//第一级节点
            newbinding.XPath = "PID";
            RuleTree_tv.SetBinding(TreeView.ItemsSourceProperty, newbinding);

            //Binding ImageBinding = new Binding();
            //ImageBinding.Mode = BindingMode.OneWay;
            //ImageBinding.Source = myXmlDataProvider;
            //newbinding.XPath = "PID";
            

            //image3.Source = ICO.getICO("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");
        }

        private void button1_Click_1(object sender, RoutedEventArgs e)//Fun test button
        {
            //List<string> stringarray = new List<string>(10);
            //stringarray.Add("string 0");
            //stringarray.Add("string 1");
            //PID myPID = new PID();
            //myPID.ID = "myname";
            //myPID.Children = stringarray;
            //List<PID> myPIDArray = new List<PID>(10);
            //myPIDArray.Add(myPID);
            //myPIDArray.Add(myPID);
            //myPIDArray.Add(myPID);
            //XML_W_R.XMLWrite(myPIDArray);

            sendmessage(0x501);
            //SetBindingOfTreeView("E:/Allowed.xml");
            //XML_W_R.XMLRead("test.xml");

            //string a = ICO.setICO(@"D:\Projects\Visual C\C_Sharp\SRTP\Ad-BAT\Ad-BAT\Resources\default.ico");
            //string b=ICO.getICOFP("QQ");
            //WinRaise();

            //Setting mysetting = new Setting();
            //mysetting.Mode = 10;
            //mysetting.ProtectType = 3;

            //XML_W_R.WriteSetting(mysetting, "setting.xml");
            //XML_W_R.ReadSetting("setting.xml");
        }


        private void DeleteItem_Menu_Click(object sender, RoutedEventArgs e)
        {
            //Add your code to handle this event(delete the selected item in treeview)

            //object Value = RuleTree_tv.SelectedValue;
            //MessageBox.Show(Value.ToString());
            MessageBoxResult result = MessageBox.Show("您确定要将该PID从列表中移除吗?", "确认", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result==MessageBoxResult.Yes)
            {
                DeleteItem();
                SetBindingOfTreeView(FileName);
            }
        }

        private void RuleTree_tv_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Right)
            {
                SelectItemByRightClick(this.RuleTree_tv);
            }
        }
        public static TreeViewItem SelectItemByRightClick(ItemsControl source)
        {
            /////////////////////////////////////////////////////////////////////////////
            //
            // Note: 对于TreeViewItem来说，如果被选中了，那肯定是它的父节点也被选中了
            //
            /////////////////////////////////////////////////////////////////////////////
            if (!(source is TreeView) && !(source is TreeViewItem))
            {
                throw new ArgumentException("只支持参数为TreeView或者TreeViewItem", "source");
            }

            foreach (object item in source.Items)
            {
                TreeViewItem currentItem = source.ItemContainerGenerator.ContainerFromItem(item) as TreeViewItem;
                Point mousePosition = Mouse.GetPosition(currentItem);

                Rect itemRect = VisualTreeHelper.GetDescendantBounds(currentItem);

                // 可能是选中的项，也可能是选中项的父节点
                if (itemRect.Contains(mousePosition))
                {
                    // 看看是不是它的孩子被选中了，否则就是它自己被选中了               
                    if (currentItem.IsExpanded)
                    {
                        // 只判断展开的项
                        TreeViewItem selectedItem = SelectItemByRightClick(currentItem);
                        if (selectedItem != null)
                        {
                            selectedItem.IsSelected = true;
                            return selectedItem;
                        }
                    }
                    currentItem.IsSelected = true;
                    return currentItem;
                }
            }
            return null;
        } 
        private void DeleteItem()
        {
            List<PID> PIDLIST = new List<PID>();
            PIDLIST = XML_W_R.XMLRead(FileName);

            PIDLIST.RemoveAll(FindItem);

            XML_W_R.XMLWrite(PIDLIST, FileName);
            PIDLIST.Clear();
        }
        private bool FindItem(PID pid)
        {
            
            if (pid.ID==RuleTree_tv.SelectedValue.ToString())
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void Save_btn_Click(object sender, RoutedEventArgs e)
        {
            SaveSetting();
            MessageBox.Show("设置已保存!", "Save");
        }
    }

}
