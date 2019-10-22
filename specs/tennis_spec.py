# tennis_spec.py

from mamba import description, context, it
from expects import expect, equal

import tennis

with description('Tennis:') as self:
  with context('we need a referee, '):
    with before.all:
        print('----context.court.before.all')
    with after.all:
        print('----context.court.after.all')
    with context('we need a court, '):
      #with before.all:
      #  print('  ++++context.court.before.all')
      #with after.all:
      #  print('  ++++context.court.after.all')
      with before.each:
        print('  ****context.court.before.each')
      with after.each:
        print('  ****context.court.after.each')
      with it('prepare the court'):
        print('start to sweep the court')
        print('finish sweeping the court')
        expect(True).to(equal(True))
      with context('We need two players'):
        #with before.all:
        #  print('    ====context.players.before.all')
        #with after.all:
        #  print('    ====context.players.after.all')
        with before.each:
          print('    $$$$context.players.before.each')
        with after.each:
          print('    $$$$context.players.after.each')
    
        with it('starts with 0 - 0 score'):
          rafa_nadal = "Rafa Nadal"
          roger_federer = "Roger Federer"
          print('Start a game')
          game = tennis.Game(rafa_nadal, roger_federer)
  
          expect(game.score()).to(equal((0, 0)))
          print('End a game')
