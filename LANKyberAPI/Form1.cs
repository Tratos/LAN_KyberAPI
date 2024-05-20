using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace LANKyberAPI
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Logger.box = rtb1;
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!SSLServer._exit)
            {
                SSLServer.Stop();
            }
            Application.Exit();
        }

        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            if(checkBox1.Checked)
            {
                Globals.basicMode = true;
            }

            Globals.backendIP = toolStripTextBox1.Text;
            Globals.backendPort = toolStripTextBox2.Text;
            toolStripButton1.Enabled = false;
            SSLServer.Start();
        }
    }
}
