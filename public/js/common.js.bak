// 共享的登出功能
function logout() {
  fetch('/logout', {
    method: 'DELETE',
    credentials: 'include'
  })
  .then(response => {
    if (response.ok) {
      window.location.href = '/login.html';
    } else {
      alert('登出失败，请稍后再试');
    }
  })
  .catch(err => {
    alert('网络错误，请稍后再试');
  });
}

// 页面加载完成后初始化事件监听器
document.addEventListener('DOMContentLoaded', function() {
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
});