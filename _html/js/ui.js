$(document).ready(function(){
	if( window.location.pathname == "/" ) {
		getofficers();
	}
	$("#sideclear").click(function(){
		$("#sidesearch").val("");
		$(".nav-sidebar a.nav-header").show();
	});
	$("#sidesearch").keydown(function(e){
		var search_term = $(this).val();
		if( search_term.length == 0 ) {
			$("ul.nav-sidebar > li > a.nav-header").show();
		}
		else {
			$("ul.nav-sidebar > li > a.nav-header").hide();
			$("ul.nav-sidebar > li > a.nav-header:contains("+search_term+")").show();
		}
	});
    
    $(".date").each(function(i,item){
    	var date = new Date( parseInt(item.innerHTML)*1000 );
    	item.innerHTML = date.toLocaleString();
    });
    $('[data-toggle=offcanvas]').click(function() {
	    $('.row-offcanvas').toggleClass('active');
	  });
    
    $(".ajaxbtn").click(function(e){
    	e.preventDefault();
    	$this = $(this);
    	$.post( this.href, null, function(a){
    		if( a.success == 1 ) {
    			var action = $this.data("action")
    			eval(action);
    		}
    	}, 'json');
    })
    
    $tzselect = $("select#timezone");
    if( window['moment'] ) {
    	$.each( moment.tz.names(), function(index,tzname) {
    		$tzselect.append('<option value="'+tzname+'">'+tzname+'</option>');
    	});
    }
		
    timezone = $("input#setting_timezone").val();
    if( typeof timezone === "undefined" ) timezone = "local";
    var avail = $("form#changesettings").serializeArray();
	for( var i = 0; i < avail.length; i++ ) {
		var $e = $("[name='"+avail[i].name+"']");
		$e.val( $("input#setting_"+avail[i].name).val() );
	}
	init_forms();
});

function init_forms(element) {
	if( typeof element === "undefined" ) var target = $("form")
	else var target = element;

	target.submit(function(e){
    	e.preventDefault();
    	var $this = $(this);
    	var btn = $this.find("button[type='submit']"); 
    	btn.button('loading');
    	$.post( this.action, $this.serializeArray(), function(a){
    		var action = window[btn.data("action")];
    		if(typeof action == "function") {
    			action(a);
    		}
    		btn.button('reset');
    		$this.parents(".modal").modal("hide");
    	}, 'json').fail(function(){alert("Request Failure");btn.button("reset")});
    }); 
}
function initapptree() {
	//Application tree
    $('.filetree li:has(ul)').addClass('parent_li').find(' > span').attr('title', 'Collapse this branch');
    $('.filetree li.parent_li > span').on('click', function (e) {
        var children = $(this).parent('li.parent_li').find(' > ul > li');
        if (children.is(":visible")) {
            children.hide('fast');
            $(this).attr('title', 'Expand this branch').find(' > i').addClass('fa-folder').removeClass('fa-folder-open');
        } else {
            children.show('fast');
            $(this).attr('title', 'Collapse this branch').find(' > i').addClass('fa-folder-open').removeClass('fa-folder');
        }
        e.stopPropagation();
    });
}

var timezone;
function datefieldsupdate() {
    $(".date:not(.processed)").each(function(i,item){
    	var $item = $(item); 
    	var timestamp = parseInt(item.innerHTML);
    	var date = null;
    	if( !isNaN(timestamp) && timestamp != 0) {
    		timestamp *= 1000;
    		if( timezone == "local" || !window['moment'] ) {
    			date = new Date(timestamp).toLocaleFormat()
    		}
    		else {
    			date = moment(timestamp).tz(timezone).toString();
    		}
    		$item.parent("td").attr("data-order", timestamp);
        	item.innerHTML = date;
    	}
    	$item.addClass("processed");
    });
}
function removerow($row) {
	$row.find("td").fadeOut('fast',function(){
		$row.remove();
	});
}
function newcase(a) {
	window.location = "/case/scan/" + a.case_id;
}
function getofficers() {
	$.post( "/getofficers", null, function(a){
		$officers = $("#officers");
		$officers.html("")
		for(var i=0;i<a.length;i++) {
			var o = new Option(a[i].officer_name,a[i].officer_id);
			$officers.append(o);
		}
	}, 'json');
}

function parseuri(){
	
}
function onpageload() {
	$('.tree-toggle').click(function () {
		$(this).parent().children('ul.tree').toggle(200);
	});
	
	$("a.file-nav").click(function(e){
		e.preventDefault();
		$("#content").load("case/"+$(this).attr("rel"),function(){
			onsubload();
		});
	});
}

function onsubload() {
	
	/*$(".tab-pane table").each(function(i,item){
		
		$(item).dataTable();
	});
	*/
	
}

function slidepanelbody(e) {
	var $e = $(e);
	$e.parents(".panel").find(".panel-body").slideToggle();
	$e.find("i").toggleClass("fa-plus fa-minus");
}
function toggleallpanels(e,nohtml) {
	var $e = $(e); 
	$e.parents(".filetree").find(".panel").toggle(0);
	$e.find("i").toggleClass( "fa-plus fa-minus" );
	var txt = $e.find("span")
	txt.html( txt.html() == "Expand" ? "Retract" : "Expand" );
}
function togglefileinfo(e) {
	var $e = $(e);
	$e.parent().next("div.panel").toggle(400,function(){
		$e.toggleClass("panelbtn")
	});
}
function hideshow(e) {
	var $e = $(e)
	$e.next("pre,div").toggle(400,function(){
		$e.children("span").toggleClass("glyphicon-chevron-down glyphicon-chevron-up");
	});
}


$(document).ready(function() {
    $("div.bhoechie-tab-menu>div.list-group>a").click(function(e) {
        e.preventDefault();
        $(this).siblings('a.active').removeClass("active");
        $(this).addClass("active");
        var index = $(this).index();
        $("div.bhoechie-tab>div.bhoechie-tab-content").removeClass("active");
        $("div.bhoechie-tab>div.bhoechie-tab-content").eq(index).addClass("active");
    });
});

function anav2view(el,prevent) {
	var $el = $(el);
	var $menu_entry = $('.nav a[href="'+$el.attr("href")+'"]');
	$menu_entry.parent().parent().find("li.active").removeClass("active");
	$menu_entry.parent().addClass("active");
	$menu_entry[0].scrollIntoView();
}

function selfreload(a) {
	window.location.reload();
}