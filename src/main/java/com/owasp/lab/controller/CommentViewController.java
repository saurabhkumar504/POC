package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * Renders comments as HTML.
 *
 * REMEDIATION (OWASP A03:2021 - Injection / XSS - Stored):
 * Every user-controlled field (author, body) is HTML-escaped via Spring's
 * {@link HtmlUtils#htmlEscape(String)} before concatenation.  The rendered
 * page therefore displays the literal "<script>" text rather than
 * executing it.
 */
@RestController
@RequestMapping("/comments")
public class CommentViewController {

    private final CommentService commentService;

    public CommentViewController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    public String viewAll() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body><h1>Comments</h1>");
        List<Comment> comments = commentService.findAll();
        for (Comment c : comments) {
            // REMEDIATION (A03:2021 - XSS): HTML-escape user-controlled
            // fields before concatenating them into the response.
            sb.append("<div class='comment'>")
              .append("<b>").append(HtmlUtils.htmlEscape(c.getAuthor())).append(":</b> ")
              .append(HtmlUtils.htmlEscape(c.getBody()))
              .append("</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    @GetMapping(value = "/{id}", produces = MediaType.TEXT_HTML_VALUE)
    public String viewOne(@PathVariable Long id) {
        Comment c = commentService.findById(id);
        if (c == null) {
            return "<html><body>Not found</body></html>";
        }
        // REMEDIATION (A03:2021 - XSS): HTML-escape user-controlled fields.
        return "<html><body><h1>Comment</h1><div><b>"
                + HtmlUtils.htmlEscape(c.getAuthor()) + ":</b> "
                + HtmlUtils.htmlEscape(c.getBody()) + "</div></body></html>";
    }
}
