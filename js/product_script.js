let menu = document.querySelector('#menu-btn');
let navbar = document.querySelector('.navbar');

menu.onclick = () => {
    menu.classList.toggle('fa-times');
    navbar.classList.toggle('active');
};

window.onscroll = () => {
    menu.classList.remove('fa-times');
    navbar.classList.remove('active');
};

$(document).ready(function() {

  $('.color-choose input').on('click', function() {
      var color = $(this).attr('data-image');

      $('.active').removeClass('active');
      $('.left-column img[data-image = ' + color + ']').addClass('active');
      $(this).addClass('active');
  });

});
