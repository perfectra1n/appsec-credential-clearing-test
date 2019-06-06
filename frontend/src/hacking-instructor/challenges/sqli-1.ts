import {
  waitForInputToHaveValue,
  waitForInputToNotHaveValue,
  waitForElementToGetClicked,
  waitInMs,
  sleep
} from '../helpers/helpers'
import { ChallengeInstruction } from '../'

export const SqlOneInstructions: ChallengeInstruction = {
  name: 'Login Admin',
  hints: [
    {
      text:
        "To start this challenge, you'll have to log out first.",
      fixture: '#navbarLogoutButton',
      unskippable: true,
      async resolved () {
        while (true) {
          if (localStorage.getItem('token') === null) {
            break
          }
          await sleep(100)
        }
      }
    },
    {
      text:
        "Let's try if we find a way to log in with the administrator's user account. To begin, go to the _Login_ page.",
      fixture: '#navbarLoginButton',
      unskippable: true,
      async resolved () {
        while (true) {
          if (window.location.hash === '#/login') {
            break
          }
          await sleep(100)
        }
      }
    },
    {
      text: 'To find a way around the normal login process we will try to use an SQL Injection (SQLi) attack.',
      fixture: '#email',
      resolved: waitInMs(8000)
    },
    {
      text: "A good starting point for simple SQL Injections is to insert quotation marks (like `\"` or `'`). These mess with the syntax of an insecurely concatenated query and might give you feedback if an endpoint is vulnerable or not.",
      fixture: '#email',
      resolved: waitInMs(15000)
    },
    {
      text: "Start with entering `'` in the **email field**.",
      fixture: '#email',
      resolved: waitForInputToHaveValue('#email', "'")
    },
    {
      text: "Now put anything in the **password field**. It doesn't matter what.",
      fixture: '#password',
      resolved: waitForInputToNotHaveValue('#password', '')
    },
    {
      text: 'Press the _Log in_ button',
      fixture: '#loginButton',
      resolved: waitForElementToGetClicked('#loginButton')
    },
    {
      text: "Nice! Do you see the red `[object Object]` error at the top? Unfortunately it isn't really telling us much about what went wrong...",
      fixture: '#loginButton',
      resolved: waitInMs(10000)
    },
    {
      text: 'Maybe you will be able to find out more information about the error in the JavaScript console or the network tab of your browser!',
      fixture: '#loginButton',
      resolved: waitInMs(10000)
    },
    {
      text: 'Did you spot the error message with the `SQLITE_ERROR` and the entire SQL query in the console output? If not, keep the console open and click _Log in_ again. Then inspect the occuring log message closely.',
      fixture: '#loginButton',
      resolved: waitInMs(15000)
    },
    {
      text: "Let's try to manipulate the query a bit to make it useful. Try out typing `' OR true` into the **email field**.",
      fixture: '#email',
      resolved: waitForInputToHaveValue('#email', "' OR true")
    },
    {
      text: 'Now click the _Log in_ button again.',
      fixture: '#loginButton',
      resolved: waitForElementToGetClicked('#loginButton')
    },
    {
      text: 'Mhh... The query is still invalid? Can you see why from the new error in the console?',
      fixture: '#loginButton',
      resolved: waitInMs(8000)
    },
    {
      text: "We need to make sure that the rest of the query after our injection doesn't get executed. Any Ideas?",
      fixture: '#loginButton',
      resolved: waitInMs(8000)
    },
    {
      text: 'You can comment out anything after your injection payload from query using comments in SQL. In SQLite databases you can use `--` for that.',
      fixture: '#loginButton',
      resolved: waitInMs(10000)
    },
    {
      text: 'So, type in "\' OR true--" in the email field.',
      fixture: '#email',
      resolved: waitForInputToHaveValue('#email', "' OR true--")
    },
    {
      text: 'Press the _Log in_ button again and sit back...',
      fixture: '#loginButton',
      resolved: waitForElementToGetClicked('#loginButton')
    },
    {
      text:
        'That worked, right?! To see with whose account you just logged in, click the _User Profile_ image.',
      fixture: '#userMenuButton',
      resolved: waitForElementToGetClicked('#userMenuButton')
    },
    {
      text:
        '🎉 Congratulations! You are logged in as the administrator of the shop!',
      fixture: '#searchQuery',
      resolved: waitInMs(10000)
    }
  ]
}
