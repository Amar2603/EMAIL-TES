(function(){
  function safeParams(getParams){
    try{
      const p = (typeof getParams === 'function') ? getParams() : new URLSearchParams();
      return (p instanceof URLSearchParams) ? p : new URLSearchParams();
    }catch(e){
      return new URLSearchParams();
    }
  }

  function mountSharedSidebar(options){
    const opts = options || {};
    const mountId = opts.mountId || 'sidebarMount';
    const mountEl = document.getElementById(mountId);
    if(!mountEl){
      return;
    }

    const active = opts.active || 'email_verification';
    const isFindActive = active === 'find_email' ? 'active' : '';
    const isEmailActive = active === 'email_verification' ? 'active' : '';
    const isCreditActive = active === 'credit_balance' ? 'active' : '';

    mountEl.innerHTML =
      '<aside class="sidebar">' +
        '<div class="logo">E-fy</div>' +
        '<div class="menu">' +
          '<div class="menu-item ' + isFindActive + '" id="navFindEmail"><span class="menu-icon">Q</span>Find Email</div>' +
          '<div class="menu-item ' + isEmailActive + '" id="navEmailVerification"><span class="menu-icon">@</span>Email Verification</div>' +
          '<div class="menu-item ' + isCreditActive + '" id="navCreditBalance"><span class="menu-icon">R</span>Credit Balance</div>' +
        '</div>' +
        '<div class="credit-panel">' +
          '<div class="credit-pill"><span>Credits</span><span id="creditsValue">100</span></div>' +
          '<button class="buy-credits" id="buyCreditsBtn" type="button">Rs Buy Credits</button>' +
        '</div>' +
      '</aside>';

    if(typeof opts.credits !== 'undefined'){
      updateSharedSidebarCredits(opts.credits);
    }

    const paramsGetter = function(){ return safeParams(opts.getParams); };

    const findEmail = document.getElementById('navFindEmail');
    const emailVerification = document.getElementById('navEmailVerification');
    const creditBalance = document.getElementById('navCreditBalance');
    const buyBtn = document.getElementById('buyCreditsBtn');

    if(findEmail){
      findEmail.addEventListener('click', function(){
        window.location.href = '/home/index.html';
      });
    }

    if(emailVerification){
      emailVerification.addEventListener('click', function(){
        window.location.href = '/verify/index.html?' + paramsGetter().toString();
      });
    }

    if(creditBalance){
      creditBalance.addEventListener('click', function(){
        window.location.href = '/billing/index.html?' + paramsGetter().toString();
      });
    }

    if(buyBtn){
      buyBtn.addEventListener('click', function(){
        if(typeof opts.onBuyCredits === 'function'){
          opts.onBuyCredits();
          return;
        }
        window.location.href = '/billing/index.html?' + paramsGetter().toString();
      });
    }
  }

  function updateSharedSidebarCredits(value){
    const creditsEl = document.getElementById('creditsValue');
    if(creditsEl){
      creditsEl.textContent = String(Math.max(0, Number(value) || 0));
    }
  }

  window.mountSharedSidebar = mountSharedSidebar;
  window.updateSharedSidebarCredits = updateSharedSidebarCredits;
})();
