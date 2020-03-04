using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.IO.Ports;

namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
        private SerialPort rs232;
        public Form1()
        {
            InitializeComponent();
        }
        void Receivedata(Object sender, SerialDataReceivedEventArgs data)
        {
            string text = "[收到]" + ((SerialPort)sender).ReadLine() + '\n';
            richTextBox.AppendText(text);
         

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            rs232 = new SerialPort();
            string[] AllPortName = SerialPort.GetPortNames();
            rs232.Close();
            combleBox.Items.AddRange(AllPortName);
            combleBox.Text = AllPortName[0];
            rs232.PortName = AllPortName[0];
            rs232.Open();
            
          this.rs232.DataReceived += new SerialDataReceivedEventHandler(Receivedata);
        }


        private void richTextBox1_TextChanged(object sender, EventArgs e)
        {

        }


        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            string data = "[发送]" + textBox.Text + '\n';
            textBox.Text = string.Empty;
            this.rs232.Write(data);
            richTextBox.AppendText(data);

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            rs232.Close();
            rs232.PortName = ((ComboBox)sender).Text;
            rs232.Open();

        }
    }
}
