using System.Configuration;

namespace Aegis
{
    public partial class LoginPage : Form
    {
        public LoginPage()
        {
            InitializeComponent();
        }

        private void hamburgerButton_Click(object sender, EventArgs e)
        {
            if (menuPanel.Width == 200)
            {
                menuPanel.Width = 50;
            }
            else
            {
                menuPanel.Width = 200;
            }
        }

        private void LoginPage_Load(object sender, EventArgs e)
        {
            menuPanel.Width = 50;
        }

        private void LoadPage(UserControl page)
        {
            panelContent.Controls.Clear(); // remove previous page
            page.Dock = DockStyle.Fill;
            panelContent.Controls.Add(page);
        }

        private void registerBtn_Click(object sender, EventArgs e)
        {
            LoadPage(new RegisterPage());
        }
    }
}
