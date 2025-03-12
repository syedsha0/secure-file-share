// JavaScript for Secure File Share

document.addEventListener("DOMContentLoaded", () => {
  // File upload preview
  const fileInput = document.getElementById("file")
  const filePreview = document.getElementById("file-preview")

  if (fileInput && filePreview) {
    fileInput.addEventListener("change", function () {
      const file = this.files[0]
      if (file) {
        const fileSize = (file.size / 1024).toFixed(2)
        filePreview.innerHTML = `
                    <div class="alert alert-info">
                        <strong>${file.name}</strong> (${fileSize} KB)
                    </div>
                `
      } else {
        filePreview.innerHTML = ""
      }
    })
  }

  // Auto-dismiss alerts after 5 seconds
  const alerts = document.querySelectorAll(".alert:not(.alert-info)")
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.opacity = "0"
      alert.style.transition = "opacity 1s"
      setTimeout(() => {
        alert.remove()
      }, 1000)
    }, 5000)
  })

  // Confirm password validation
  const passwordForm = document.getElementById("password-form")
  if (passwordForm) {
    passwordForm.addEventListener("submit", (e) => {
      const password = document.getElementById("password").value
      const confirmPassword = document.getElementById("confirm-password").value

      if (password !== confirmPassword) {
        e.preventDefault()
        document.getElementById("password-error").textContent = "Passwords do not match"
        document.getElementById("password-error").style.display = "block"
      }
    })
  }
})

