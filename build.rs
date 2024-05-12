fn main() {
    embuild::espidf::sysenv::output();
    minify_web()
}

fn minify_web() {
    // return early if the web.html did not change from the last build.
    println!("cargo:rerun-if-changed=src/web.html");
    let web_html = std::fs::read("src/web.html").unwrap();
    let cfg = minify_html::Cfg {
        minify_css: true,
        minify_js: true,
        ..Default::default()
    };
    let minified = minify_html::minify(&web_html, &cfg);
    // write the minified html to a file in the OUT_DIR
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = std::path::Path::new(&out_dir).join("out.html");
    std::fs::write(out_path, minified).unwrap();
}
