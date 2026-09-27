from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='dispatch')
class CustomLoginView(LoginView):
    template_name = 'authentication/login.html'
    redirect_authenticated_user = True
    
    def get_success_url(self):
        url = self.get_redirect_url()
        return url or reverse_lazy('dashboard:index')



