import { ComponentFixture, TestBed } from '@angular/core/testing';

import { BlockedUsers } from './blocked-users';

describe('BlockedUsers', () => {
  let component: BlockedUsers;
  let fixture: ComponentFixture<BlockedUsers>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BlockedUsers],
    }).compileComponents();

    fixture = TestBed.createComponent(BlockedUsers);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
