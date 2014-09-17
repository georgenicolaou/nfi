function hashnav() {
	var hash = window.location.hash;
	if( hash.length == 0 ) return;
	var page = hash.slice(1);
	var url = page.replace(" ", "%20");
	var loading = $('<div class="loading">').html(
		$('<span>').append(
			$('<i class="fa fa-spinner spin">'),
			" Loading..."
		)
	);
	$("#content").html(loading);
	$("#content").load( url, function( response, status, xhr ){
		if( status == "error" ) {
			loading.html("Error: " + xhr.status + " " + xhr.statusText);
			return;
		}
		datefieldsupdate();
		$('[data-toggle="tooltip"]').tooltip();
		$("table.dtcapable").dataTable({
			"iDisplayLength":100,
			/*"sScrollX" : "100%",*/
			"bScrollCollapse": true,
		});
		var $menuli = $(".sidebar-nav a[href='"+hash+"']").parent("li");
		if( !$menuli.hasClass("active") ) {
			$(".sidebar-nav li.active").removeClass("active");
			$menuli.addClass("active");
			var $parent = $menuli.parent(".sub.lvl-2");
			if( $parent ) {
				$parent.parent("li").addClass("active");
				$parent.slideDown("fast");
			}
		}
	});
}

$(document).ready(function(){
	$(window).on("hashchange", function(e){
		hashnav();
	});
	hashnav();
	
	$('.sidebar-nav a').click(function(e){
		//e.preventDefault();
		var $item = $(this).parent();
		var $list = $item.parent();
		var dropdown = ($item.data("toggle") == "cdropdown") ? true:false;
		
		if( $item.hasClass("active") && $item.children(".sub").length ) {
			$item.children(".sub").slideUp("fast");
			$item.removeClass("active");
		}
		else {
			$list.find(".active .sub").slideUp("fast");
			$list.find(".active").removeClass("active");
			$item.addClass("active");
			$item.children(".sub").slideDown("fast");
		}
	});
	if( window.location.hash.length == 0 ) {
		//$('a [href="#/dashboard"]').click();
		window.location.hash = "/dashboard/index/"+CASE_ID;
	}
	$("ul.lvl-2").each(function(i,el){
		var $this = $(this);
		if( $this.outerHeight() >= parseInt($this.css("max-height") ) ) {
			$this.niceScroll({horizrailenabled:false});
		} 
	});
})

