document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');
    const errorMessage = document.getElementById('errorMessage');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(form);

        try {
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                window.location.href = '/monitor';
            } else {
                errorMessage.style.display = 'block';
                // Hide error message after 3 seconds
                setTimeout(() => {
                    errorMessage.style.display = 'none';
                }, 3000);
            }
        } catch (error) {
            console.error('Error:', error);
            errorMessage.style.display = 'block';
        }
    });
});