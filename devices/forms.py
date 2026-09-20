from django import forms
from .models import Device

class DeviceForm(forms.ModelForm):
    api_token = forms.CharField(
        widget=forms.PasswordInput(render_value=True, attrs={'class': 'form-input'}),
        help_text="Token REST API. Kosongkan (atau biarkan simbol) jika tidak ingin mengubah token saat ini."
    )

    class Meta:
        model = Device
        fields = ['name', 'ip_address', 'port']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.api_token_encrypted:
            self.fields['api_token'].required = False
            self.fields['api_token'].initial = '********'
        else:
            self.fields['api_token'].required = True

    def clean_api_token(self):
        token = self.cleaned_data.get('api_token')
        if token == '********':
            return ''
        return token

    def save(self, commit=True):
        device = super().save(commit=False)
        new_token = self.cleaned_data.get('api_token')
        
        if new_token:
            device.set_token(new_token)
        
        if commit:
            device.save()
        return device