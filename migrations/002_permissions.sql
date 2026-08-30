-- Nexus Campus Step 2: permission catalog and explicit role-default mode.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

ALTER TABLE user_role_assignments
  ADD COLUMN IF NOT EXISTS use_role_defaults BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS actor_subject TEXT;

INSERT INTO permissions (permission_key, label, domain) VALUES
  ('*', 'All permissions', 'core'),
  ('profile.read', 'Read own profile', 'profile'),
  ('student.read', 'Read student records', 'student'),
  ('student.manage', 'Manage student records', 'student'),
  ('program.*', 'Manage program domain', 'program'),
  ('course.read', 'Read courses', 'course'),
  ('course.manage', 'Manage courses', 'course'),
  ('course.*', 'Manage course domain', 'course'),
  ('section.read', 'Read class sections', 'section'),
  ('section.manage', 'Manage class sections', 'section'),
  ('section.*', 'Manage section domain', 'section'),
  ('attendance.read', 'Read attendance', 'attendance'),
  ('attendance.manage', 'Record attendance', 'attendance'),
  ('attendance.adjust', 'Adjust attendance', 'attendance'),
  ('attendance.*', 'Manage attendance domain', 'attendance'),
  ('material.read', 'Read learning materials', 'material'),
  ('material.manage', 'Manage learning materials', 'material'),
  ('material.*', 'Manage material domain', 'material'),
  ('assignment.submit', 'Submit assignments', 'assignment'),
  ('assignment.manage', 'Manage assignments', 'assignment'),
  ('assessment.manage', 'Manage assessments', 'assessment'),
  ('assessment.*', 'Manage assessment domain', 'assessment'),
  ('grade.read', 'Read grades', 'grade'),
  ('grade.write', 'Write grades', 'grade'),
  ('finance.read', 'Read finance records', 'finance'),
  ('finance.*', 'Manage finance domain', 'finance'),
  ('finance.invoice.write', 'Issue finance invoices', 'finance'),
  ('report.read', 'Read reports', 'report'),
  ('report.finance', 'Read finance reports', 'report'),
  ('audit.read', 'Read audit logs', 'audit'),
  ('schedule.read', 'Read schedules', 'schedule'),
  ('schedule.manage', 'Manage schedules', 'schedule'),
  ('schedule.*', 'Manage schedule domain', 'schedule'),
  ('admin.grant.manage', 'Delegate admin authority', 'administration')
ON CONFLICT (permission_key) DO NOTHING;

WITH role_permission_map(role_key, permission_key) AS (
  VALUES
    ('super_admin', '*'),
    ('institution_admin', '*'),
    ('faculty_admin', '*'),
    ('program_admin', '*'),
    ('course_admin', '*'),
    ('section_admin', '*'),
    ('academic_admin', 'student.read'),
    ('academic_admin', 'student.manage'),
    ('academic_admin', 'program.*'),
    ('academic_admin', 'course.*'),
    ('academic_admin', 'section.*'),
    ('academic_admin', 'attendance.*'),
    ('academic_admin', 'assessment.*'),
    ('academic_admin', 'schedule.*'),
    ('academic_admin', 'report.read'),
    ('academic_admin', 'audit.read'),
    ('finance_admin', 'finance.*'),
    ('finance_admin', 'student.read'),
    ('finance_admin', 'report.finance'),
    ('instructor', 'course.read'),
    ('instructor', 'section.read'),
    ('instructor', 'attendance.manage'),
    ('instructor', 'material.*'),
    ('instructor', 'assessment.manage'),
    ('instructor', 'grade.read'),
    ('instructor', 'grade.write'),
    ('student', 'profile.read'),
    ('student', 'course.read'),
    ('student', 'section.read'),
    ('student', 'attendance.read'),
    ('student', 'material.read'),
    ('student', 'assignment.submit'),
    ('student', 'grade.read'),
    ('student', 'finance.read')
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role_permission_map map
JOIN roles r ON r.role_key = map.role_key
JOIN permissions p ON p.permission_key = map.permission_key
ON CONFLICT DO NOTHING;
