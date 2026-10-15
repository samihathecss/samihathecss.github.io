/**
 * Samiha Tasnim - Cybersecurity Portfolio
 * Vanilla JavaScript for navigation, smooth scroll, and animations
 */

(function () {
  "use strict";

  // DOM Elements
  var navToggle = document.querySelector(".nav-toggle");
  var navMenu = document.querySelector(".nav-menu");
  var navLinks = document.querySelectorAll(".nav-link");
  var navbar = document.querySelector(".navbar");
  var yearSpan = document.getElementById("year");

  // Mobile Menu Toggle
  function toggleMobileMenu(event) {
    event.stopPropagation();
    var isOpen = navMenu.classList.contains("active");
    navMenu.classList.toggle("active");
    navToggle.classList.toggle("active");
    navToggle.setAttribute("aria-expanded", !isOpen);
  }

  function closeMenuOnOutsideClick(event) {
    var isClickInside = navMenu.contains(event.target) || navToggle.contains(event.target);
    if (!isClickInside) {
      navMenu.classList.remove("active");
      navToggle.classList.remove("active");
      navToggle.setAttribute("aria-expanded", "false");
      document.removeEventListener("click", closeMenuOnOutsideClick);
    }
  }

  if (navToggle) {
    navToggle.addEventListener("click", toggleMobileMenu);
  }

  // Smooth Scroll & Active Nav
  function handleNavLinkClick(event) {
    event.preventDefault();
    var href = event.currentTarget.getAttribute("href");
    var targetElement = document.querySelector(href);
    if (targetElement) {
      if (navMenu.classList.contains("active")) {
        navMenu.classList.remove("active");
        navToggle.classList.remove("active");
        navToggle.setAttribute("aria-expanded", "false");
      }
      targetElement.scrollIntoView({ behavior: "smooth", block: "start" });
      history.pushState(null, null, href);
      updateActiveNavLink(event.currentTarget);
    }
  }

  function updateActiveNavLink(clickedLink) {
    for (var i = 0; i < navLinks.length; i++) {
      navLinks[i].classList.remove("active");
    }
    clickedLink.classList.add("active");
  }

  // Scroll-based Navbar & Active Link
  function handleScroll() {
    if (navbar) {
      navbar.classList.toggle("scrolled", window.scrollY > 50);
    }
    updateActiveLinkOnScroll();
  }

  function updateActiveLinkOnScroll() {
    var sections = document.querySelectorAll("section[id]");
    var current = "";
    for (var i = 0; i < sections.length; i++) {
      var section = sections[i];
      var sectionTop = section.offsetTop;
      var sectionHeight = section.offsetHeight;
      var scrollPosition = window.scrollY + 80;
      if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
        current = section.getAttribute("id");
      }
    }
    for (var j = 0; j < navLinks.length; j++) {
      navLinks[j].classList.remove("active");
      if (navLinks[j].getAttribute("href") === "#" + current) {
        navLinks[j].classList.add("active");
      }
    }
  }

  // Section Reveal on Scroll
  function revealSections() {
    if (!("IntersectionObserver" in window)) {
      return;
    }
    var observerOptions = {
      root: null,
      rootMargin: "0px",
      threshold: 0.1
    };
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          observer.unobserve(entry.target);
        }
      });
    }, observerOptions);

    var revealElements = document.querySelectorAll(
      ".about-content, .projects-grid, .services-grid, .contact-grid"
    );
    revealElements.forEach(function (el) {
      observer.observe(el);
    });
  }

  // Footer Year
  function setFooterYear() {
    if (yearSpan) {
      yearSpan.textContent = new Date().getFullYear();
    }
  }

  // Animation styles (injected to avoid jank on initial load)
  function injectAnimationStyles() {
    var style = document.createElement("style");
    style.textContent =
      ".about-content,\n" +
      ".projects-grid,\n" +
      ".services-grid,\n" +
      ".contact-grid {\n" +
      "  opacity: 0;\n" +
      "  transform: translateY(30px);\n" +
      "  transition: opacity 0.6s ease, transform 0.6s ease;\n" +
      "}\n" +
      ".about-content.revealed,\n" +
      ".projects-grid.revealed,\n" +
      ".services-grid.revealed,\n" +
      ".contact-grid.revealed {\n" +
      "  opacity: 1;\n" +
      "  transform: translateY(0);\n" +
      "}\n";
    document.head.appendChild(style);
  }

  // Initialize
  function init() {
    for (var i = 0; i < navLinks.length; i++) {
      navLinks[i].addEventListener("click", handleNavLinkClick);
    }
    window.addEventListener("scroll", handleScroll);
    setFooterYear();
    injectAnimationStyles();
    revealSections();
    handleScroll();

    // Handle initial hash
    var initialHash = window.location.hash;
    if (initialHash) {
      var initialLink = document.querySelector('.nav-link[href="' + initialHash + '"]');
      if (initialLink) {
        initialLink.classList.add("active");
      }
    }

    // Handle back/forward
    window.addEventListener("popstate", function () {
      var hash = window.location.hash || "#hero";
      var activeLink = document.querySelector('.nav-link[href="' + hash + '"]');
      if (activeLink) {
        for (var k = 0; k < navLinks.length; k++) {
          navLinks[k].classList.remove("active");
        }
        activeLink.classList.add("active");
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
