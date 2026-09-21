from django import forms
from .models import ComplianceRule

class ComplianceRuleForm(forms.ModelForm):
    class Meta:
        model = ComplianceRule
        fields = '__all__'
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'impact': forms.Textarea(attrs={'rows': 2}),
            'recommendation': forms.Textarea(attrs={'rows': 2}),
        }