# How to Add AGENTS.md to Existing Projects

## Example AI Prompt

To add an AGENTS.md to this project, use the following prompt with your AI assistant:

```
Add an AGENTS.md to this project. Follow the process and template in https://github.com/avaje/avaje-oauth2/blob/HEAD/docs/guides/how-to-add-AGENTS-md.md. It should guide both AI and human developers to the official agent/developer guides for all major frameworks used (e.g., Avaje OAuth2, Avaje Nima, Ebean ORM). Use the latest links and match the style of AGENTS.md in sibling projects if available.
```

---

This guide standardizes the process for adding an AGENTS.md to any project using avaje-oauth2 (or similar), ensuring both AI and human developers have fast, accurate access to actionable, framework-specific instructions.

## Purpose

AGENTS.md is a developer/AI agent onboarding file. It:
- Points to official, agent/developer step-by-step guides for all major frameworks used (e.g., Avaje OAuth2, Avaje Nima, Ebean ORM)
- Lists key tasks (JWT verification setup, role/scope authorization, multi-issuer migration, etc.)
- Ensures consistency and discoverability for both AI and human contributors

## Steps

1. **Clarify the Audience and Purpose**
   - Confirm AGENTS.md is for developer/AI agent onboarding (not background jobs).
2. **Check for Reference AGENTS.md**
   - Look for AGENTS.md in sibling projects and align style/content.
3. **Use the Template Below**
   - Update framework links and project-specific notes as needed.
4. **Review and Commit**
   - Get feedback from a maintainer or lead before merging.

## Template

```markdown
# AI Agent Instructions

This project uses [avaje-oauth2](https://github.com/avaje/avaje-oauth2) for JWT verification and OIDC login.

Before performing a library-related task, fetch and follow the relevant guide below.

---

## avaje-oauth2

Guide index: https://github.com/avaje/avaje-oauth2/tree/main/docs/guides/

Key guides (fetch and follow when performing the relevant task):

- Getting started: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/getting-started.md
- OIDC login flow: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/oidc-login-flow.md
- Role and scope authorization: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/role-and-scope-authorization.md
- Multi-issuer migration: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/multi-issuer-migration.md
- JWKS tuning: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/jwks-tuning.md
- Entra ID vs Cognito claims: https://raw.githubusercontent.com/avaje/avaje-oauth2/main/docs/guides/entra-vs-cognito-claims.md
```

## Example AI Prompt

To add an AGENTS.md to this project, use the following prompt with your AI assistant:

```
Add an AGENTS.md to this project. Follow the process and template in https://github.com/avaje/avaje-oauth2/blob/HEAD/docs/guides/how-to-add-AGENTS-md.md. It should guide both AI and human developers to the official agent/developer guides for all major frameworks used (e.g., Avaje OAuth2, Avaje Nima, Ebean ORM). Use the latest links and match the style of AGENTS.md in sibling projects if available.
```

---

- [ ] Audience and purpose clarified
- [ ] Template used and links updated
- [ ] Style matches sibling projects
- [ ] Reviewed by maintainer/lead

---
_Keep this guide up to date as frameworks and best practices evolve._
