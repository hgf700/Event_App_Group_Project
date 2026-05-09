import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SearchAndImportEvents } from './search-and-import-events';

describe('SearchAndImportEvents', () => {
  let component: SearchAndImportEvents;
  let fixture: ComponentFixture<SearchAndImportEvents>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SearchAndImportEvents],
    }).compileComponents();

    fixture = TestBed.createComponent(SearchAndImportEvents);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
