"""Checks for the report builder: what it must refuse, and what it derives.

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import copy
import json
import unittest
from pathlib import Path

import build_report as br

EXAMPLE = json.loads((Path(__file__).resolve().parent.parent / 'assets' / 'example-data.json').read_text(encoding='utf8'))


def changed(mutate):
    data = copy.deepcopy(EXAMPLE)
    mutate(data)
    return br.check(data)


class CheckTests(unittest.TestCase):
    def test_the_example_is_a_finished_report(self):
        findings = br.check(EXAMPLE)
        self.assertEqual(findings.errors, [])
        self.assertEqual(findings.needs_input, [])

    def test_a_breakdown_that_does_not_cover_every_alert_is_refused(self):
        # The failure this exists for: counts taken from a page of results.
        findings = changed(lambda d: d['tier1']['by_level'].pop())
        self.assertTrue(any('tier1.by_level sums to 249' in e for e in findings.errors), findings.errors)

    def test_a_figure_without_a_recorded_source_is_refused(self):
        findings = changed(lambda d: d['sources'].pop('tier1.alert_total'))
        self.assertTrue(any('sources["tier1.alert_total"]' in e for e in findings.errors), findings.errors)

    def test_a_source_must_say_who_and_what(self):
        findings = changed(lambda d: d['sources'].update({'tier1.alert_total': {'by': 'estimate', 'ref': 'about 1700'}}))
        self.assertTrue(any('sources["tier1.alert_total"] is missing' in e for e in findings.errors))
        findings = changed(lambda d: d['sources'].update({'tier1.alert_total': {'by': 'tool', 'ref': ' '}}))
        self.assertTrue(any('.ref is empty' in e for e in findings.errors))

    def test_the_appendix_must_name_exactly_the_offline_agents(self):
        findings = changed(lambda d: d['appendix_edr_offline'].clear())
        self.assertTrue(any('appendix_edr_offline lists 0 machines' in e for e in findings.errors), findings.errors)

    def test_online_and_offline_must_make_up_the_installed_agents(self):
        findings = changed(lambda d: d['coverage']['siem'].update({'online': 50}))
        self.assertTrue(any('coverage.siem: online (50) + offline (2)' in e for e in findings.errors))

    def test_a_ranking_out_of_order_is_refused(self):
        findings = changed(lambda d: d['tier1']['top_rules'].reverse())
        self.assertTrue(any('tier1.top_rules must be ordered' in e for e in findings.errors))

    def test_a_typed_tier2_sla_that_disagrees_with_the_counts_is_refused(self):
        findings = changed(lambda d: d['tier2']['sla'].update({'current': 100}))
        self.assertTrue(any('tier2.sla.current is 100' in e for e in findings.errors), findings.errors)

    def test_a_missing_figure_is_asked_for_not_defaulted(self):
        findings = changed(lambda d: d['tier1']['sla'].update({'current': None}))
        self.assertIn('tier1.sla.current', [path for path, _ in findings.needs_input])
        self.assertTrue(findings.blocking)

    def test_a_blank_file_separates_tool_figures_from_the_users(self):
        findings = br.check(br.blank('Acme', 'acme', 2026, 9, 7))
        paths = [path for path, _ in findings.needs_input]
        self.assertIn('tier1.alert_total', paths)
        self.assertIn('tier3.cases_total', paths)
        self.assertIn('tier1.sla.current', paths)
        # How many cases there were is the platform's to answer; whether the
        # SLA was met is the service team's.
        self.assertIn('tier3.cases_total', br.FROM_TOOLS)
        self.assertNotIn('tier1.sla.current', br.FROM_TOOLS)

    def test_a_deduction_needs_its_reason(self):
        findings = changed(lambda d: d['tier3'].update({'exclusion_reason': ''}))
        self.assertIn('tier3.exclusion_reason', [path for path, _ in findings.needs_input])


class DeriveTests(unittest.TestCase):
    def test_tier2_sla_and_the_kpi_tally_are_computed(self):
        derived = br.derive(EXAMPLE)
        self.assertEqual(derived['sla']['tier2']['current'], 96.25)
        self.assertEqual((derived['kpis_achieved'], derived['kpis_total']), (4, 4))
        self.assertEqual((derived['month'], derived['previous_month']), ('August 2024', 'July 2024'))

    def test_a_tier_below_target_is_not_counted_as_achieved(self):
        data = copy.deepcopy(EXAMPLE)
        data['tier2']['tickets_on_time'] = 60
        derived = br.derive(data)
        self.assertEqual(derived['sla']['tier2']['current'], 75.0)
        self.assertEqual(derived['kpis_achieved'], 3)

    def test_january_looks_back_to_december(self):
        data = copy.deepcopy(EXAMPLE)
        data['meta']['period'] = {'year': 2025, 'month': 1}
        self.assertEqual(br.derive(data)['previous_month'], 'December 2024')

    def test_period_bounds_are_the_whole_month_in_the_report_zone(self):
        bounds = br.period_bounds(EXAMPLE)['this_month']
        self.assertEqual(bounds['from_iso'], '2024-08-01T00:00:00+07:00')
        self.assertEqual(bounds['to_exclusive_iso'], '2024-09-01T00:00:00+07:00')
        self.assertEqual(bounds['to_ms'] - bounds['from_ms'], 31 * 86400 * 1000 - 1)


class RenderTests(unittest.TestCase):
    BRAND = {'provider_name': 'EXAMPLE SECURITY', 'provider_legal': 'Example Security', 'provider_short': 'ES',
             '_images': {}}

    def test_data_cannot_inject_markup(self):
        data = copy.deepcopy(EXAMPLE)
        data['meta']['customer_name'] = '<script>alert(1)</script>'
        self.assertNotIn('<script>alert(1)</script>', br.render(data, self.BRAND, draft=False))

    def test_a_draft_shows_what_is_missing(self):
        data = copy.deepcopy(EXAMPLE)
        data['tier1']['sla']['current'] = None
        page = br.render(data, self.BRAND, draft=True)
        self.assertIn('class="draft"', page)
        self.assertIn('N/A — the SLA figure has not been provided.', page)

    def test_a_missed_target_is_stated_not_glossed(self):
        data = copy.deepcopy(EXAMPLE)
        data['tier2']['tickets_on_time'] = 60
        page = br.render(data, self.BRAND, draft=False)
        self.assertIn('reaching 75%, below the committed SLA of 90%.', page)
        self.assertIn('<b>3/4</b>', page)


class BrandTests(unittest.TestCase):
    """Where the company's names and images are found, and what happens without them."""

    def _isolated(self, home: str, run):
        import os
        old_home, old_named, old_cwd = os.environ.get('DSH_HOME'), os.environ.pop('MSS_REPORT_BRAND', None), os.getcwd()
        os.environ['DSH_HOME'] = home
        os.chdir(home)
        try:
            return run()
        finally:
            os.chdir(old_cwd)
            os.environ.pop('DSH_HOME')
            if old_home is not None:
                os.environ['DSH_HOME'] = old_home
            if old_named is not None:
                os.environ['MSS_REPORT_BRAND'] = old_named

    def test_the_users_own_pack_outranks_the_one_beside_the_skill(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            pack = Path(home).resolve() / 'report-brand'
            pack.mkdir()
            (pack / 'brand.json').write_text(json.dumps({'provider_name': 'ACME SEC', 'provider_legal': 'Acme Sec'}))
            brand, where = self._isolated(home, lambda: br.find_brand(None))
            self.assertEqual(Path(where).resolve(), pack)
        self.assertEqual(brand['provider_name'], 'ACME SEC')
        # a partial pack is completed from the defaults rather than breaking the render
        self.assertEqual(brand['report_title'], 'MANAGED SECURITY SERVICE')

    def test_the_workspace_pack_outranks_the_users(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            order = self._isolated(home, lambda: [str(Path(c).resolve()) for c in br.brand_candidates(None)])
            root = str(Path(home).resolve())
        self.assertLess(order.index(f'{root}/.dsh/report-brand'), order.index(f'{root}/report-brand'))
        self.assertEqual(order[-1], str((br.SKILL_DIR / 'brand').resolve()))

    def test_a_report_still_renders_with_the_neutral_default(self):
        # The skill ships inside the application with no company's pack; the
        # first report on a new machine must come out, visibly unbranded.
        page = br.render(EXAMPLE, {**br.DEFAULT_BRAND, '_images': {}}, draft=False)
        self.assertIn('YOUR COMPANY', page)
        self.assertIn('Tier 1 – Your Company', page)


WEEKLY_DIR = Path(__file__).resolve().parent.parent / 'assets' / 'templates' / 'weekly-summary'
WEEKLY = json.loads((WEEKLY_DIR / 'template.json').read_text(encoding='utf8'))
WEEKLY_DATA = json.loads((WEEKLY_DIR / 'example-data.json').read_text(encoding='utf8'))


def weekly(mutate):
    data = copy.deepcopy(WEEKLY_DATA)
    mutate(data)
    return br.check_template(data, WEEKLY)


class TemplateTests(unittest.TestCase):
    BRAND = {**br.DEFAULT_BRAND, '_images': {}}

    def test_the_shipped_template_is_valid_and_its_example_is_finished(self):
        self.assertEqual(br.validate_template(WEEKLY), [])
        findings = br.check_template(WEEKLY_DATA, WEEKLY)
        self.assertEqual((findings.errors, findings.needs_input), ([], []))

    def test_a_template_is_found_by_name_in_the_working_directory_first(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            mine = Path(tmp) / 'report-templates' / 'weekly-summary'
            mine.mkdir(parents=True)
            (mine / 'template.json').write_text(json.dumps({**WEEKLY, 'title': 'MINE'}), encoding='utf8')
            before = os.getcwd()
            os.chdir(tmp)
            try:
                self.assertEqual(br.find_template('weekly-summary').resolve(), mine.resolve())
                self.assertEqual(br.list_templates()[0][2], 'MINE')
            finally:
                os.chdir(before)

    def test_the_skeleton_written_without_an_example_is_itself_valid(self):
        self.assertEqual(br.validate_template(br.STARTER), [])

    def test_a_block_reading_an_undeclared_figure_is_reported_to_the_author(self):
        broken = copy.deepcopy(WEEKLY)
        broken['blocks'].append({'type': 'bullet', 'text': 'Cases: {cases.total}'})
        broken['blocks'].append({'type': 'table', 'rows': 'actions', 'columns': [{'head': 'Owner', 'field': 'owner'}]})
        problems = br.validate_template(broken)
        self.assertTrue(any('{cases.total} is not a field' in p for p in problems), problems)
        self.assertTrue(any('no column "owner"' in p for p in problems), problems)

    def test_a_declared_figure_with_no_value_is_asked_for_from_the_right_party(self):
        findings = weekly(lambda d: (d['alerts'].update({'total': None}), d['tickets'].update({'on_time': None})))
        self.assertEqual({path for path, _ in findings.needs_input}, {'alerts.total', 'tickets.on_time'})

    def test_template_rows_must_add_up_and_carry_a_source(self):
        findings = weekly(lambda d: d['alerts']['by_level'].pop())
        self.assertTrue(any('alerts.by_level sums to 365 but alerts.total is 412' in e for e in findings.errors), findings.errors)
        findings = weekly(lambda d: d['sources'].pop('tickets.on_time'))
        self.assertTrue(any('sources["tickets.on_time"] is missing' in e for e in findings.errors))

    def test_a_template_for_a_range_refuses_a_monthly_period(self):
        findings = weekly(lambda d: d['meta'].update({'period': {'year': 2026, 'month': 9}}))
        self.assertTrue(any('for a range period' in e for e in findings.errors), findings.errors)

    def test_periods_of_each_cycle_and_the_equal_span_before(self):
        week = br.period_of(WEEKLY_DATA)
        self.assertEqual((week['label'], week['previous_label']),
                         ('21/09/2026 – 27/09/2026', '14/09/2026 – 20/09/2026'))
        quarter = br.period_of({'meta': {'period': {'year': 2026, 'quarter': 1}}})
        self.assertEqual((quarter['label'], quarter['previous_label'], quarter['to']), ('Q1 2026', 'Q4 2025', '31/03/2026'))
        self.assertEqual(br.period_bounds(WEEKLY_DATA)['this_period']['to_exclusive_iso'], '2026-09-28T00:00:00+07:00')

    def test_computed_values_conditions_and_wording_follow_the_figures(self):
        page = br.render(WEEKLY_DATA, self.BRAND, draft=False, template=WEEKLY)
        self.assertIn('23/24 tickets were processed on time, achieving the SLA target', page)
        self.assertIn('WEEKLY SECURITY MONITORING SUMMARY', page)
        self.assertIn('There was no incident on Acme Corp', page)
        data = copy.deepcopy(WEEKLY_DATA)
        data['tickets']['on_time'] = 12
        data['incidents'] = [{'title': 'Web shell', 'summary': '<b>contained</b>'}]
        page = br.render(data, self.BRAND, draft=False, template=WEEKLY)
        self.assertIn('reaching 50%, below the SLA target', page)
        self.assertIn('<b>0/1</b>', page)
        self.assertIn('Web shell: &lt;b&gt;contained&lt;/b&gt;', page)
        self.assertNotIn('There was no incident', page)

    def test_a_missing_figure_shows_as_na_in_a_template_draft(self):
        data = copy.deepcopy(WEEKLY_DATA)
        data['alerts']['total'] = None
        data['alerts']['top_rules'] = None
        page = br.render(data, self.BRAND, draft=True, template=WEEKLY)
        self.assertIn('<b><span class="na">N/A</span></b>', page)
        self.assertIn('N/A — not collected yet.', page)

    def test_a_blank_data_file_lists_every_declared_figure(self):
        data = br.blank_from_template(WEEKLY, 'weekly-summary', 'Acme', 'acme', {'from': '2026-09-21', 'to': '2026-09-27'}, 7)
        self.assertIsNone(data['alerts']['by_level'])
        self.assertEqual(data['commentary'], '')
        needs = {path for path, _ in br.check_template(data, WEEKLY).needs_input}
        self.assertEqual(needs, set(WEEKLY['fields']) - {'commentary'})


if __name__ == '__main__':
    unittest.main()
