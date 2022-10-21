#  Google-dorking / Effective Googling

## Resources
- [Blackhat Google Hacking for Penetration Testers](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf)
- [Advanced search operators list](https://docs.google.com/document/d/1ydVaJJeL1EYbWtlfj9TPfBTE5IBADkQfZrQaBZxqXGs/edit) as of 2019/07/23
- [Google Search Operators: The Complete List ](https://ahrefs.com/blog/google-advanced-search-operators/#find-qa-threads)

## Operators and Search Tips
1. Use *Boolean* search terms: `AND`, `OR`,`NOT` (there is an implied AND between search terms)
    ```sql
    red OR blue OR orange fruit
    ```
1. Use quotes to search for terms in the exact order specified (good for error messages and disambiguation)
    ```sql
    "ls: cannot access"
    ```
1. Exclude non-necessary words
    ```sql
    How did Frederick Douglass affect the Civil War?
    ```
    vs
    ```sql
    Frederick Douglass Civil War OR "Frederick Douglass" "Civil War"
    ```
1. Search for a range of numbers or prices with "`..`"
    ```sh
    headphones $50..$100
    ```
1. Exclude words from search with "`-`" symbol
    ```sql
    jaguar speed -car
    ```
1. Restrict the domain with `site:`
    ```
    site:.edu shays' rebellion
    ```
1. Search for related sites with `related:`
    ```
    related:snopes.com
    ```
1. See Google's cached version of a site with `cache:`
    ```
    cache:arstechnica.com
    ```
1. Restrict results to pages containing the query terms in the *anchor text* on links to the page with `allinanchor:` and `inanchor:`
    ```
    allinanchor: best restaurant Sunnyvale  
    ```
    ```
    inanchor:sales offer 2011
    ```
    **NOTE**: `inanchor` only applies to the next immediate term
1. Restrict results to pages containing the query terms in the *text* of the page with `allintext:` and `intext:`
    ```
    allintext: camping tent stove  
    ```
    ```
    intext:Victorian artists
    ```
    **NOTE**: `intext` only applies to the next immediate term
1. Restrict results to pages containing the query terms in the *title* of the page with `allintitle:` and `intitle:`
    ```
    allintitle: flu shot  
    ```
    ```
    intitle:flu shot
    ```
    **NOTE**: `intitle` only applies to the next immediate term
1. Restrict results to pages containing the query terms in the *URL* with `allinurl:` and `inurl:`
    ```
    allinurl:google faq  
    ```
    ```
    inurl:google faq
    ```
    **NOTE**: `inurl` only applies to the next immediate term
1. Use `AROUND` to limit results to those documents where `term1` appears within `n` words of `term2`.
    ```
    search AROUND 3 engine
    ```
1. Use `before:` to find results that were published before a given date
    ```
    avengers endgame before:2018-1-1
    ```
1. Use `after:` to find results that were published before a given date
    ```
    avengers endgame AFTER:2020-1-1
    ```
1. Use `define` to get definitions for words and phrases
    ```
    define peruse
    ```
1. Use `filetype:suffix` to limit search to pages ending with the specified filetype
    ```
    filetype:pptx
    ```
1. Use `*` (wildcards) to fill in the blanks. It matches up to 5 terms.
    ```
    Obama voted * on the * bill
    ```
1. Use [`Advanced Search`](http://www.google.com/advanced_search). You can easily select parameters from here.
