package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.model.User;
import com.owasp.lab.service.CommentService;
import com.owasp.lab.service.ProductService;
import com.owasp.lab.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Server-rendered HTML UI for the OWASP lab.
 *
 * Each handler:
 *  - returns a Thymeleaf view name (NOT JSON),
 *  - applies the same authorization rules as the matching /api/* endpoint,
 *  - escapes all user-controlled fields in templates via th:text (not th:utext).
 *
 * The JSON /api/* endpoints are NOT modified by this class.  The
 * existing curl / script flow continues to work.
 */
@Controller
public class UIController {

    private final ProductService products;
    private final UserService users;
    private final CommentService comments;

    public UIController(ProductService products,
                        UserService users,
                        CommentService comments) {
        this.products = products;
        this.users = users;
        this.comments = comments;
    }

    // -----------------------------------------------------------------
    // Login page (rendered by the UI; Spring Security handles POST).
    // -----------------------------------------------------------------
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    // -----------------------------------------------------------------
    // Dashboard / home
    // -----------------------------------------------------------------
    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal UserDetails me) {
        model.addAttribute("me", me);
        model.addAttribute("productCount", products.findAll().size());
        model.addAttribute("userCount", users.findAll().size());
        model.addAttribute("commentCount", comments.findAll().size());
        model.addAttribute("isAdmin", isAdmin(me));
        return "dashboard";
    }

    // -----------------------------------------------------------------
    // Products
    // -----------------------------------------------------------------
    @GetMapping("/products")
    public String productsPage(Model model) {
        model.addAttribute("products", products.findAll());
        return "products";
    }

    // -----------------------------------------------------------------
    // Users (admin-only, matching the /api/users rule)
    // -----------------------------------------------------------------
    @GetMapping("/users")
    public String usersPage(Model model, @AuthenticationPrincipal UserDetails me) {
        boolean admin = isAdmin(me);
        // Match the JSON API: ADMIN sees everyone, USER sees only
        // themselves.  The /api/users endpoint throws 403 for non-admin
        // callers; the UI matches by limiting what is rendered.
        List<User> visible = admin
                ? users.findAll()
                : users.findAll().stream()
                        .filter(u -> me != null && me.getUsername().equals(u.getUsername()))
                        .toList();
        model.addAttribute("users", visible);
        model.addAttribute("isAdmin", admin);
        return "users";
    }

    // -----------------------------------------------------------------
    // Comments (read + add)
    // -----------------------------------------------------------------
    @GetMapping("/comments")
    public String commentsPage(Model model, @AuthenticationPrincipal UserDetails me) {
        model.addAttribute("comments", comments.findAll());
        model.addAttribute("me", me);
        return "comments";
    }

    @PostMapping("/comments")
    public String addComment(@RequestParam(name = "author", required = false) String author,
                             @RequestParam(name = "body") String body,
                             @AuthenticationPrincipal UserDetails me,
                             RedirectAttributes flash) {
        if (body == null || body.isBlank()) {
            flash.addFlashAttribute("error", "Comment body cannot be empty");
            return "redirect:/comments";
        }
        String resolvedAuthor = (author == null || author.isBlank())
                ? (me != null ? me.getUsername() : "anonymous")
                : author;
        // Length cap to mirror the @Column(length = 2000) on Comment.body.
        String safeBody = body.length() > 2000 ? body.substring(0, 2000) : body;
        comments.save(new Comment(resolvedAuthor, safeBody));
        flash.addFlashAttribute("info", "Comment posted (rendered with HTML escaping)");
        return "redirect:/comments";
    }

    // -----------------------------------------------------------------
    // Transfer (form shim that reuses the same domain logic as the
    // JSON /api/transfer endpoint, but with a server-side shim that
    // avoids CSRF / content-type / auth-header concerns in the form
    // flow).
    // -----------------------------------------------------------------
    @GetMapping("/transfer")
    public String transferPage(Model model) {
        model.addAttribute("users", users.findAll());
        return "transfer";
    }

    @PostMapping("/transfer")
    public String doTransfer(@RequestParam("fromId") Long fromId,
                             @RequestParam("toId") Long toId,
                             @RequestParam("amount") Double amount,
                             @AuthenticationPrincipal UserDetails me,
                             RedirectAttributes flash) {
        if (me == null) {
            return "redirect:/login";
        }
        User from = users.findByIdUnsafe(fromId);
        User to   = users.findByIdUnsafe(toId);
        if (from == null || to == null) {
            flash.addFlashAttribute("error", "User not found");
            return "redirect:/transfer";
        }
        if (!isAdmin(me) && !me.getUsername().equals(from.getUsername())) {
            flash.addFlashAttribute("error", "You can only transfer from your own account");
            return "redirect:/transfer";
        }
        if (amount == null || amount <= 0) {
            flash.addFlashAttribute("error", "Amount must be positive");
            return "redirect:/transfer";
        }
        if (from.getBalance() == null || from.getBalance() < amount) {
            flash.addFlashAttribute("error", "Insufficient funds");
            return "redirect:/transfer";
        }
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);
        users.save(from);
        users.save(to);
        flash.addFlashAttribute("info",
                "Transferred " + amount + " from " + from.getUsername()
                        + " to " + to.getUsername());
        return "redirect:/transfer";
    }

    // -----------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------
    private static boolean isAdmin(UserDetails me) {
        if (me == null) return false;
        return me.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
