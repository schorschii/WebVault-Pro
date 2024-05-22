function activateWindowMouseDrag(divWindow, divTitleBar, divParentWindow=null) {
	var mousePosition;
	var offsetx = 0;
	var offsety = 0;
	var isDown = false;

	if(divParentWindow) {
		let offset = 35;
		if(window.innerWidth < 500) offset = 0;
		divWindow.style.top = (parseInt(divParentWindow.style.top)+offset) + 'px';
		divWindow.style.left = (parseInt(divParentWindow.style.left)+offset) + 'px';
	}

	divWindow.addEventListener('mousedown', function(e) {
		bringToFront(divWindow);
	}, true);

	divTitleBar.addEventListener('mousedown', function(e) {
		isDown = true;
		let left = parseInt(divWindow.style.left.replace('px', ''));
		let right = parseInt(divWindow.style.top.replace('px', ''));
		if(isNaN(left)) left = 0;
		if(isNaN(right)) right = 0;
		offsetx = divTitleBar.offsetLeft - e.clientX + left;
		offsety = divTitleBar.offsetTop - e.clientY + right;
	}, true);

	document.addEventListener('mouseup', function() {
		isDown = false;
	}, true);

	document.addEventListener('mousemove', function(event) {
		if(isDown) {
			event.preventDefault();
			mousePosition = {
				x : event.clientX,
				y : event.clientY
			};
			divWindow.style.left = (mousePosition.x + offsetx) + 'px';
			divWindow.style.top  = (mousePosition.y + offsety) + 'px';
		}
	}, true);
}

let windowZIndexCounter = 1;
function bringToFront(divWindow) {
	divWindow.style.zIndex = windowZIndexCounter;
	windowZIndexCounter += 1;
}

let animationWindowOut = {
	keyframes: [
		{ transform: 'scale(1)', easing: 'ease' },
		{ transform: 'scale(0)', easing: 'ease' },
	],
	options: { duration: 200, iterations: 1 },
};
let animationWindowIn = {
	keyframes: [
		{ transform: 'scale(0)', easing: 'ease' },
		{ transform: 'scale(1)', easing: 'ease' },
	],
	options: { duration: 200, iterations: 1 },
};

function windowOpenAnimation(window) {
	window.classList.remove('invisible');
	window.animate(
		animationWindowIn.keyframes,
		animationWindowIn.options
	);
	bringToFront(window);
}

function windowCloseAction(div, remove=true) {
	return function(e) {
		let animation = div.animate(
			animationWindowOut.keyframes,
			animationWindowOut.options
		);
		animation.onfinish = (event) => {
			if(remove) div.remove();
			else div.classList.add('invisible');
		};
	};
}

let animationLoginOut = {
	keyframes: [
		{ opacity: 1, easing: 'ease' },
		{ opacity: 0, easing: 'ease' },
	],
	options: { duration: 200, iterations: 1 }
};
let animationLoginIn = {
	keyframes: [
		{ opacity: 0, easing: 'ease' },
		{ opacity: 1, easing: 'ease' },
	],
	options: { duration: 200, iterations: 1 }
};

function loginToVaultAnimation() {
	// show main window with animation
	let animation = divLoginContainer.animate(
		animationLoginOut.keyframes,
		animationLoginOut.options
	);
	animation.onfinish = (event) => {
		btnLogin.classList.remove('loading');
		btnLogin.disabled = false;
		divLoginContainer.classList.add('invisible');
		divVaultContainer.classList.remove('invisible');
		divVaultContainer.style.top = ((window.innerHeight / 2) - (divVaultContainer.clientHeight / 2) - 20)+'px';
		divVaultContainer.style.left = ((window.innerWidth / 2) - (divVaultContainer.clientWidth / 2))+'px';
		divVaultContainer.animate(
			animationLoginIn.keyframes,
			animationLoginIn.options
		);
	};
	let animation2 = forkMe.animate(
		animationLoginOut.keyframes,
		animationLoginOut.options
	);
	animation2.onfinish = (event) => {
		forkMe.classList.add('invisible');
	};
}

function vaultToLoginAnimation() {
	let animation = divVaultContainer.animate(
		animationLoginOut.keyframes,
		animationLoginOut.options
	);
	animation.onfinish = (event) => {
		ulEntriesTree.innerHTML = '';
		divLoginContainer.classList.remove('invisible');
		divVaultContainer.classList.add('invisible');
		divLoginContainer.animate(
			animationLoginIn.keyframes,
			animationLoginIn.options
		);
	};
	forkMe.classList.remove('invisible');
	forkMe.animate(
		animationLoginIn.keyframes,
		animationLoginIn.options
	);
}
