function activateMouseDragForParent(div) {
	var mousePosition;
	var offsetx = 0;
	var offsety = 0;
	var isDown = false;

	div.addEventListener('mousedown', function(e) {
		isDown = true;
		let left = parseInt(div.parentElement.style.left.replace("px",""));
		let right = parseInt(div.parentElement.style.top.replace("px",""));
		if(isNaN(left)) left = 0;
		if(isNaN(right)) right = 0;
		offsetx = div.offsetLeft - e.clientX + left;
		offsety = div.offsetTop - e.clientY + right;
	}, true);

	document.addEventListener('mouseup', function() {
		isDown = false;
	}, true);

	document.addEventListener('mousemove', function(event) {
		event.preventDefault();
		if (isDown) {
			mousePosition = {
				x : event.clientX,
				y : event.clientY
			};
			div.parentElement.style.left = (mousePosition.x + offsetx) + 'px';
			div.parentElement.style.top  = (mousePosition.y + offsety) + 'px';
		}
	}, true);
}
