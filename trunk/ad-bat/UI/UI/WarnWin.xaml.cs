using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AdBAT
{
    /// <summary>
    /// Interaction logic for WarnWin.xaml
    /// </summary>
    public partial class WarnWin : Window
    {
        public static int hwnd = 0;//当前窗口句柄

        System.Windows.Threading.DispatcherTimer timer = new System.Windows.Threading.DispatcherTimer();
        System.Windows.Threading.DispatcherTimer timer2 = new System.Windows.Threading.DispatcherTimer();
        int timecost=30;
        public WarnWin()
        {
            InitializeComponent();
            timer.Tick+=new EventHandler(timer_Tick);
            timer.Interval = TimeSpan.FromSeconds(0.1);
            timer.IsEnabled = true;
            timer.Start();

            timer2.Tick+=new EventHandler(timer2_Tick);
            timer2.Interval = TimeSpan.FromSeconds(1);
            timer2.IsEnabled = true;
            timer2.Start();
        }
        void timer_Tick(object sender,EventArgs e)
        {
            WinRaise();
        }
        void timer2_Tick(object sender,EventArgs e)
        {
            if (timecost==0)
            {
                timer2.Stop();
                WinDown();
            }
            time_la.Content = timecost.ToString()+"  秒后";
            timecost--;
        }
        private void OK_Btn_Click(object sender, RoutedEventArgs e)
        {
            WinDown();
            timer2.Stop();
        }
        private void WinRaise()
        {
            System.Windows.Forms.Screen myScreen = System.Windows.Forms.Screen.PrimaryScreen;
            int SHeight = myScreen.WorkingArea.Height;
            int SWidth = myScreen.WorkingArea.Width;
            this.Left = SWidth - this.Width;
            this.Top = SHeight;
            while (true)
            {
                this.Top -= 25;
                if (this.Top <= SHeight - this.Height)//完全展现
                {
                    timer.Stop();
                    timer.IsEnabled = false;
                    break;
                }
                System.Threading.Thread.Sleep(10);
            }

        }
        private void WinDown()
        {
            SendMSG();
            System.Windows.Forms.Screen myScreen = System.Windows.Forms.Screen.PrimaryScreen;
            int SHeight = myScreen.WorkingArea.Height;
            int SWidth = myScreen.WorkingArea.Width;
            this.Left = SWidth - this.Width;
            this.Top = SHeight - this.Height;
            while (true)
            {
                this.Top += 25;
                if (this.Top >= SHeight)//退出视线
                {
                    break;
                }
                System.Threading.Thread.Sleep(10);
            }
            this.Close();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            hwnd = Win32.FindWindow(null, "Ad-BAT");
            System.Windows.Forms.Screen myScreen = System.Windows.Forms.Screen.PrimaryScreen;
            int SHeight = myScreen.WorkingArea.Height;
            int SWidth = myScreen.WorkingArea.Width;
            this.Left = SWidth - this.Width;
            this.Top = SHeight;
            try
            {
                Message_tb.Text = File.ReadAllText("temp.tmp");
                File.Delete("temp.tmp");
            }
            catch (System.Exception)
            {
                Message_tb.Text = "";
            }
        }
        private void SendMSG()
        {
            if (Deny_rbtn.IsChecked==true)
            {
                Win32.SendMessage(hwnd, 0x502, 10, 10);

            }
            if (Allow_rbtn.IsChecked==true)
            {
                Win32.SendMessage(hwnd, 0x503, 10, 10);
            }
            if (Next_rbtn.IsChecked==true)
            {
                Win32.SendMessage(hwnd, 0x504, 10, 10);
            }
        }
    }
    
}
