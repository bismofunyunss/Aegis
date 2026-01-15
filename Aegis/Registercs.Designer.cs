namespace Aegis
{
    partial class RegisterPage
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
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

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            UsernameLbl = new Label();
            pwLbl = new Label();
            pwBox = new MaskedTextBox();
            confirmPwBox = new MaskedTextBox();
            confirmPwLbl = new Label();
            userTxt = new TextBox();
            registerBtn = new Button();
            panel1 = new Panel();
            panel1.SuspendLayout();
            SuspendLayout();
            // 
            // UsernameLbl
            // 
            UsernameLbl.AutoSize = true;
            UsernameLbl.Font = new Font("Segoe UI Variable Display", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            UsernameLbl.ForeColor = Color.WhiteSmoke;
            UsernameLbl.Location = new Point(14, 10);
            UsernameLbl.Name = "UsernameLbl";
            UsernameLbl.Size = new Size(121, 32);
            UsernameLbl.TabIndex = 0;
            UsernameLbl.Text = "Username";
            // 
            // pwLbl
            // 
            pwLbl.AutoSize = true;
            pwLbl.Font = new Font("Segoe UI Variable Display", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            pwLbl.ForeColor = Color.WhiteSmoke;
            pwLbl.Location = new Point(14, 79);
            pwLbl.Name = "pwLbl";
            pwLbl.Size = new Size(114, 32);
            pwLbl.TabIndex = 2;
            pwLbl.Text = "Password";
            // 
            // pwBox
            // 
            pwBox.BackColor = Color.Gray;
            pwBox.Location = new Point(14, 114);
            pwBox.Name = "pwBox";
            pwBox.Size = new Size(419, 31);
            pwBox.TabIndex = 3;
            // 
            // confirmPwBox
            // 
            confirmPwBox.BackColor = Color.Gray;
            confirmPwBox.Location = new Point(14, 181);
            confirmPwBox.Name = "confirmPwBox";
            confirmPwBox.Size = new Size(419, 31);
            confirmPwBox.TabIndex = 5;
            // 
            // confirmPwLbl
            // 
            confirmPwLbl.AutoSize = true;
            confirmPwLbl.Font = new Font("Segoe UI Variable Display", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            confirmPwLbl.ForeColor = Color.WhiteSmoke;
            confirmPwLbl.Location = new Point(14, 146);
            confirmPwLbl.Name = "confirmPwLbl";
            confirmPwLbl.Size = new Size(206, 32);
            confirmPwLbl.TabIndex = 4;
            confirmPwLbl.Text = "Confirm Password";
            // 
            // userTxt
            // 
            userTxt.BackColor = Color.Gray;
            userTxt.Location = new Point(14, 45);
            userTxt.Name = "userTxt";
            userTxt.Size = new Size(419, 31);
            userTxt.TabIndex = 6;
            // 
            // registerBtn
            // 
            registerBtn.BackColor = Color.Gray;
            registerBtn.Font = new Font("Segoe UI Variable Display", 9F, FontStyle.Regular, GraphicsUnit.Point, 0);
            registerBtn.ForeColor = Color.WhiteSmoke;
            registerBtn.Location = new Point(14, 218);
            registerBtn.Name = "registerBtn";
            registerBtn.Size = new Size(419, 45);
            registerBtn.TabIndex = 7;
            registerBtn.Text = "&Register Account";
            registerBtn.UseVisualStyleBackColor = false;
            registerBtn.Click += registerBtn_Click;
            // 
            // panel1
            // 
            panel1.Controls.Add(UsernameLbl);
            panel1.Controls.Add(registerBtn);
            panel1.Controls.Add(pwLbl);
            panel1.Controls.Add(userTxt);
            panel1.Controls.Add(pwBox);
            panel1.Controls.Add(confirmPwBox);
            panel1.Controls.Add(confirmPwLbl);
            panel1.Location = new Point(111, 15);
            panel1.Name = "panel1";
            panel1.Size = new Size(450, 326);
            panel1.TabIndex = 8;
            // 
            // RegisterPage
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Color.Gray;
            Controls.Add(panel1);
            Name = "RegisterPage";
            Size = new Size(564, 430);
            panel1.ResumeLayout(false);
            panel1.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private Label UsernameLbl;
        private Label pwLbl;
        private MaskedTextBox pwBox;
        private MaskedTextBox confirmPwBox;
        private Label confirmPwLbl;
        private TextBox userTxt;
        private Button registerBtn;
        private Panel panel1;
    }
}
