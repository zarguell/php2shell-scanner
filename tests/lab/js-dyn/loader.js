// loader bundle: StringTable joined at runtime, NO static .js ref to it.
var lang = document.documentElement.lang || "en";
(window.$ ? $.getScript : function(u){ var s=document.createElement("script"); s.src=u; document.head.appendChild(s); })("jsAd/StringTable_" + lang + ".js");
