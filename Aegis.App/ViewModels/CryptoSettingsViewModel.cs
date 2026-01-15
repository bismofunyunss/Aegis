using System.ComponentModel;
using System.Runtime.CompilerServices;
using Aegis.App;

public class CryptoSettingsViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private int _pbkdf2Iterations;

    public CryptoSettingsViewModel()
    {
        _pbkdf2Iterations = Settings.Default.PBKF2;
    }

    public int Pbkdf2Iterations
    {
        get => _pbkdf2Iterations;
        set
        {
            if (_pbkdf2Iterations == value)
                return;

            _pbkdf2Iterations = value;
            Settings.Default.PBKF2 = value;
            Settings.Default.Save();

            OnPropertyChanged();
        }
    }

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

