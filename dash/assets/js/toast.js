window.addEventListener('DOMContentLoaded', function() {
    window.showToast = function(message, type = 'success') {
        const toastArea = document.getElementById('toast-area');
        if (!toastArea) {
            console.error('toast-area não encontrado no DOM!');
            return;
        }
        const colors = {
            success: 'bg-green-600 text-white',
            error: 'bg-red-600 text-white',
            info: 'bg-blue-600 text-white',
            warning: 'bg-yellow-500 text-black',
        };
        const icons = {
            success: '<svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>',
            error: '<svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>',
            info: '<svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01"/></svg>',
            warning: '<svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01"/></svg>',
        };
        const toast = document.createElement('div');
        toast.className = `flex items-center px-4 py-3 rounded shadow-lg mb-2 text-sm font-medium ${colors[type] || colors.success} opacity-0 translate-y-24 transition-all duration-600`;
        toast.innerHTML = `${icons[type] || ''}<span>${message}</span>`;
        toastArea.appendChild(toast);
        // Trigger animação de entrada (de baixo para cima)
        setTimeout(() => {
            toast.classList.remove('opacity-0', 'translate-y-24');
            toast.classList.add('opacity-100', 'translate-y-0');
        }, 10);
        // Saída: de cima para baixo
        setTimeout(() => {
            toast.classList.remove('translate-y-0');
            toast.classList.add('translate-y-24');
            toast.classList.remove('opacity-100');
            toast.classList.add('opacity-0');
            setTimeout(() => toast.remove(), 600);
        }, 4000);
    };
}); 