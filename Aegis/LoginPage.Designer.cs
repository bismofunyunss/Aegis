namespace Aegis
{
    partial class LoginPage
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            menuPanel = new Panel();
            registerBtn = new Button();
            loginBtn = new Button();
            hamburgerButton = new Button();
            panelContent = new Panel();
            menuPanel.SuspendLayout();
            SuspendLayout();
            // 
            // menuPanel
            // 
            menuPanel.BackColor = Color.DimGray;
            menuPanel.Controls.Add(registerBtn);
            menuPanel.Controls.Add(loginBtn);
            menuPanel.Controls.Add(hamburgerButton);
            menuPanel.Dock = DockStyle.Left;
            menuPanel.Location = new Point(0, 0);
            menuPanel.Name = "menuPanel";
            menuPanel.Size = new Size(200, 329);
            menuPanel.TabIndex = 0;
            // 
            // registerBtn
            // 
            registerBtn.BackColor = Color.DimGray;
            registerBtn.FlatAppearance.BorderSize = 0;
            registerBtn.FlatStyle = FlatStyle.Flat;
            registerBtn.ForeColor = Color.LightGray;
            registerBtn.Location = new Point(3, 109);
            registerBtn.Name = "registerBtn";
            registerBtn.Size = new Size(191, 34);
            registerBtn.TabIndex = 1;
            registerBtn.Text = "&Register";
            registerBtn.UseVisualStyleBackColor = false;
            registerBtn.Click += registerBtn_Click;
            // 
            // loginBtn
            // 
            loginBtn.BackColor = Color.DimGray;
            loginBtn.FlatAppearance.BorderSize = 0;
            loginBtn.FlatStyle = FlatStyle.Flat;
            loginBtn.ForeColor = Color.LightGray;
            loginBtn.Location = new Point(3, 69);
            loginBtn.Name = "loginBtn";
            loginBtn.Size = new Size(191, 34);
            loginBtn.TabIndex = 0;
            loginBtn.Text = "&Login";
            loginBtn.UseVisualStyleBackColor = false;
            // 
            // hamburgerButton
            // 
            hamburgerButton.BackColor = Color.DimGray;
            hamburgerButton.Dock = DockStyle.Top;
            hamburgerButton.FlatAppearance.BorderSize = 0;
            hamburgerButton.FlatStyle = FlatStyle.Flat;
            hamburgerButton.Font = new Font("Segoe UI", 16F, FontStyle.Regular, GraphicsUnit.Point, 0);
            hamburgerButton.ForeColor = Color.LightGray;
            hamburgerButton.Location = new Point(0, 0);
            hamburgerButton.Name = "hamburgerButton";
            hamburgerButton.Size = new Size(200, 51);
            hamburgerButton.TabIndex = 0;
            hamburgerButton.Text = "☰";
            hamburgerButton.UseVisualStyleBackColor = false;
            hamburgerButton.Click += hamburgerButton_Click;
            // 
            // panelContent
            // 
            panelContent.Dock = DockStyle.Fill;
            panelContent.Location = new Point(200, 0);
            panelContent.Name = "panelContent";
            panelContent.Size = new Size(537, 329);
            panelContent.TabIndex = 1;
            // 
            // LoginPage
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Color.Gray;
            ClientSize = new Size(737, 329);
            Controls.Add(panelContent);
            Controls.Add(menuPanel);
            Name = "LoginPage";
            Text = "Aegis";
            Load += LoginPage_Load;
            menuPanel.ResumeLayout(false);
            ResumeLayout(false);
        }

        #endregion

        private Panel menuPanel;
        private Panel panelContent;
        private Button loginBtn;
        private Button hamburgerButton;
        private Button registerBtn;
    }
}
