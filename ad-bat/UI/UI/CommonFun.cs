using System;
using System.Xml;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Media.Imaging;
using System.Windows.Data;
using System.Globalization;
using System.Windows.Interop;
using System.Runtime.InteropServices;

namespace AdBAT
{

    [StructLayout(LayoutKind.Sequential)]
    public struct FileInfoStruct
    {
        public IntPtr hIcon;
        public int iIcon;
        public int dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }
    public enum FileInfoFlags : int
    {
        SHGFI_ICON = 0x000000100,  //  get icon 
        SHGFI_DISPLAYNAME = 0x000000200,  //  get display name 
        SHGFI_TYPENAME = 0x000000400,  //  get type name 
        SHGFI_ATTRIBUTES = 0x000000800,  //  get attributes 
        SHGFI_ICONLOCATION = 0x000001000,  //  get icon location 
        SHGFI_EXETYPE = 0x000002000,  //  return exe type 
        SHGFI_SYSICONINDEX = 0x000004000,  //  get system icon index 
        SHGFI_LINKOVERLAY = 0x000008000,  //  put a link overlay on icon  SHGFI_SELECTED  = 0x000010000 ,  //  show icon in selected state 
        SHGFI_ATTR_SPECIFIED = 0x000020000,  //  get only specified attributes 
        SHGFI_LARGEICON = 0x000000000,  //  get large icon 
        SHGFI_SMALLICON = 0x000000001,  //  get small icon 
        SHGFI_OPENICON = 0x000000002,  //  get open icon 
        SHGFI_SHELLICONSIZE = 0x000000004,  //  get shell size icon 
        SHGFI_PIDL = 0x000000008,  //  pszPath is a pidl 
        SHGFI_USEFILEATTRIBUTES = 0x000000010,  //  use passed dwFileAttribute 
        SHGFI_ADDOVERLAYS = 0x000000020,  //  apply the appropriate overlays 
        SHGFI_OVERLAYINDEX = 0x000000040   //  Get the index of the overlay 
    }
    public enum FileAttributeFlags : int
    {
        FILE_ATTRIBUTE_READONLY = 0x00000001,
        FILE_ATTRIBUTE_HIDDEN = 0x00000002,
        FILE_ATTRIBUTE_SYSTEM = 0x00000004,
        FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
        FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
        FILE_ATTRIBUTE_DEVICE = 0x00000040,
        FILE_ATTRIBUTE_NORMAL = 0x00000080,
        FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
        FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200,
        FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400,
        FILE_ATTRIBUTE_COMPRESSED = 0x00000800,
        FILE_ATTRIBUTE_OFFLINE = 0x00001000,
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
        FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
    }
    public class Win32
    {
        [DllImport("User32.dll", EntryPoint = "SendMessage")]
        public static extern int SendMessage(
           int hWnd, // handle to destination window 
           int Msg, // message 
           int wParam, // first message parameter 
           int lParam // second message parameter 
           );
        [DllImport("User32.dll", EntryPoint = "FindWindow")]
        public static extern int FindWindow(string lpClassName, string lpWindowName);

        //向窗体发送消息的函数 
        public void SendMsgToMainForm(int hwnd, int MSG)
        {
            int WINDOW_HANDLER = hwnd;
            //int WINDOW_HANDLER = FindWindow(null, @"Dialog");
            if (WINDOW_HANDLER == 0)
            {
                throw new Exception("Could not find Main window!");
            }
            SendMessage(WINDOW_HANDLER, MSG, 100, 200);
        }

        //由文件名获取图标
        [DllImport("shell32.dll ", EntryPoint = "SHGetFileInfo")]
        public static extern int GetFileInfo(string pszPath, int dwFileAttributes,
        ref  FileInfoStruct psfi, int cbFileInfo, int uFlags);
        public static Icon GetSmallIcon(string pFilePath)
        {
            FileInfoStruct _info = new FileInfoStruct();
            try
            {
                Win32.GetFileInfo(pFilePath, 0, ref  _info, Marshal.SizeOf(_info), (int)(FileInfoFlags.SHGFI_ICON | FileInfoFlags.SHGFI_SMALLICON));
                Icon myicon = Icon.FromHandle(_info.hIcon);
                return myicon;
            }
            catch (System.Exception)
            {
                return null;
            }
        }
    }
    public class PID
    {
        public string ID;
        public string myICO;
        public List<string> Children=new List<string>(1000);
    }
    public class Setting
    {
        public int Mode;//1~3
        public int ProtectType;//0~15
    }
    public class ICO
    {
        //public static Bitmap getICO(string base64string)//将以base64编码产生的字符串转换回图片
        //{
        //    byte[] bt = Convert.FromBase64String(base64string);
        //    MemoryStream stream = new MemoryStream(bt);
        //    Bitmap bitmap = new Bitmap(stream);
        //    return bitmap;
        //}
        //public static string setICO(string pathname)//将图片转换成Based64编码的字符串
        //{
        //    MemoryStream m = new MemoryStream();
        //    System.Drawing.Bitmap bp = new System.Drawing.Bitmap(System.Drawing.Image.FromFile(pathname), 16, 16);
        //    bp.Save(m, System.Drawing.Imaging.ImageFormat.Jpeg);
        //    byte[] bt = m.GetBuffer();
        //    string base64string = Convert.ToBase64String(bt);
        //    return base64string;
        //}

        public static BitmapImage getICOFB64S(string base64string)//将以base64编码产生的字符串转换回图片
        {
            byte[] bt = Convert.FromBase64String(base64string);
            MemoryStream stream = new MemoryStream(bt);
            BitmapImage myBitmapImage = new BitmapImage();
            myBitmapImage.BeginInit();
            myBitmapImage.StreamSource = stream;
            myBitmapImage.EndInit();
            return myBitmapImage;
        }
        public static string getICOFP(string ProcessName)
        {
            string pFilePath = "";

            System.Diagnostics.Process[] ps = System.Diagnostics.Process.GetProcesses();

            StringBuilder strBuilder = new StringBuilder();
            foreach (System.Diagnostics.Process p in ps)
            {
                if (p.ProcessName == "System" || p.ProcessName == "Idle") 
                {
                    continue;
                }
                else
                {
                    if (p.ProcessName == ProcessName)
                    {
                        pFilePath = p.MainModule.FileName;
                        break;
                    }
                }
            }

            Icon myicon=Win32.GetSmallIcon(pFilePath);
            if (myicon==null)
            {
                return "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAQABADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDk7mL4cWME0tz4X8RNDBctZyXUZPkGZRkoHMmM4GcHnHOKrD/hXE2ow2KaDrUFxctGIVuAQMSBShP73O0g5yB0YEZxzBf6vP8AazLapZPcW87Jb3C62kSPb/amuQGRJFff5h+9vAAxhQ4DivDcJe3uiz6lDZJd6fHa24u4tVtUVkilJ3yIBlyItkYwwP7sEls4DEf/2Q==";
            }
            else
            {
                MemoryStream mstream=new MemoryStream();
                Bitmap mybitmap = myicon.ToBitmap();
                mybitmap.Save(mstream, System.Drawing.Imaging.ImageFormat.Png);
                byte[] bt = mstream.GetBuffer();
                string base64string = Convert.ToBase64String(bt);
                return base64string;
            }
        }
    }
    public class XML_W_R
    {
        //public static void Write(PID newPID)
        //{
        //    XmlWriterSettings settings=new XmlWriterSettings();
        //    settings.Indent=true;
        //    settings.IndentChars=("    ");
        //    using (XmlWriter writer=XmlWriter.Create("Allowed.xml",settings))
        //    {
        //        writer.WriteStartElement("PID");
        //        writer.WriteElementString("ID",newPID.ID);
        //        //for (int i = 0; i < newPID.Children.Length;i++ )
        //        //{
        //        //    writer.WriteElementString("child", newPID.Children[i]);
        //        //}
        //        foreach (string child in newPID.Children)
        //        {
        //            writer.WriteElementString("child", child);
        //        }
        //        writer.WriteEndElement();
        //        writer.Flush();
        //    }
        //}
        public static void XMLWrite(List<PID> PIDs,string FileName)
        {
            XmlDocument doc = new XmlDocument();
            string strXML = "";
            //strXML = "<Ad-BAT xmlns=''>" + "<PIDLIST>";
            strXML = "<Ad-BAT xmlns=''>";
            foreach (PID pid in PIDs)
            {
                strXML += "<PID>";
                strXML += "<NAME>" + pid.ID+"</NAME>";
                strXML += "<ICO>" + pid.myICO + "</ICO>";
                foreach (string child in pid.Children)
                {
                    strXML += "<CHILD>";
                    strXML += child;
                    strXML += "</CHILD>";
                }
                strXML += "</PID>";
            }
            //strXML += "</PIDLIST>" + "</Ad-BAT>";
            strXML += "</Ad-BAT>";
            doc.LoadXml(strXML);
            try
            {
                doc.Save(FileName);
            }
            catch (System.Exception)
            {
                Directory.CreateDirectory("Events");
                doc.Save(FileName);
            }
        }
        public static List<PID> XMLRead(string SourceFile)
        {
            const int MaxItemSize = 1000;

            XmlDocument doc = new XmlDocument();
            try
            {
                doc.Load(SourceFile);
            }
            catch (System.Exception)
            {
                XMLWrite(new List<PID>(), SourceFile);
            }
            List<PID> PIDList = new List<PID>(MaxItemSize);
            XmlNodeList NodeList = doc.GetElementsByTagName("PID");
            foreach (XmlNode Node in NodeList)
            {
                PID pid = new PID();
                int index = 0;
                XmlNodeList ChildNodeList = Node.ChildNodes;
                foreach (XmlNode ChildNode in ChildNodeList)
                {
                    if (index==0)
                    {
                        pid.ID = ChildNode.InnerXml;
                    }
                    else if (index==1)
                    {
                        pid.myICO = ChildNode.InnerXml;
                    }
                    else
                    {
                        pid.Children.Add(ChildNode.InnerXml);
                    }
                    index++;
                }
                PIDList.Add(pid);
            }
            return PIDList;
        }
        public static void WriteSetting(Setting settings,string FPath)
        {
            XmlDocument doc = new XmlDocument();
            string strXML = "";
            strXML = "<Ad-BAT xmlns=''>";
            strXML += "<SETTING>";
            strXML += "<MODE>" + settings.Mode.ToString() + "</MODE>";
            strXML += "<TYPE>" + settings.ProtectType.ToString() + "</TYPE>";
            strXML += "</SETTING>";
            strXML += "</Ad-BAT>";
            doc.LoadXml(strXML);
            doc.Save(FPath);
        }
        public static Setting ReadSetting(string FPath)
        {
            XmlDocument doc = new XmlDocument();
            try
            {
                doc.Load(FPath);
            }
            catch (System.Exception)
            {
                Setting setting=new Setting();
                setting.Mode=1;
                setting.ProtectType=15;
                WriteSetting(setting, FPath);
                doc.Load(FPath);
            }
            Setting settings=new Setting();
            XmlNodeList NodeList = doc.GetElementsByTagName("SETTING");
            foreach (XmlNode Node in NodeList)
            {
                int index = 0;
                XmlNodeList ChildNodeList = Node.ChildNodes;
                foreach (XmlNode ChildNode in ChildNodeList)
                {
                    if (index == 0)
                    {
                        settings.Mode = Int32.Parse(ChildNode.InnerXml);
                    }
                    else
                    {
                        settings.ProtectType = Int32.Parse(ChildNode.InnerXml);
                    }
                    index++;
                }
            }
            return settings;
        }
    }
    [ValueConversion(typeof(String), typeof(BitmapImage))]//声明所需数据类型（相互转换的类型）
    public class DataConverter:IValueConverter
    {
        //将XML中Base64string转换成BitmapImage
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ICO.getICOFB64S((string)value);
        }
        //不需转换回来~~该方法不必重写!直接返回string
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            BitmapImage myBitmapImage=(BitmapImage)value;
            return "nothing";
        }
    }

}